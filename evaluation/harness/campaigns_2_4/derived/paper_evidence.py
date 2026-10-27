"""Read-only campaign audit and figure prototypes for the Results checkpoint.

Run from bench: .venv/bin/python campaigns_2_4/derived/paper_evidence.py
Only this derived directory is written. No benchmark, Docker or host changes.
"""
from pathlib import Path
import csv
import hashlib
import json
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from run_revision import load_specs, require_protocol_lock, NEW_RESULTS
from replacements import load_replacements
from eventlog import read as read_events


def csv_write(name, rows):
    with (HERE / name).open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def save(fig, name):
    fig.savefig(HERE / (name + '.pdf'), bbox_inches='tight')
    fig.savefig(HERE / (name + '.png'), dpi=160, bbox_inches='tight')
    plt.close(fig)


def main():
    require_protocol_lock()
    specs = load_specs('confirmatory')
    replacements = load_replacements(specs)
    rows, exposure, capacity, outages, inputs = [], [], [], [], []
    runs = []
    for position, original in enumerate(specs, 1):
        spec = replacements.get(original['id'], original)
        folder = NEW_RESULTS / spec['id']
        result = json.loads((folder / 'result.json').read_text())
        assessment = json.loads((folder / 'execution_assessment.json').read_text())
        assert assessment['execution_valid'] and not assessment['invalid_reasons']
        assert json.loads((folder / 'spec.json').read_text()) == spec == result['spec']
        for name in ['spec.json', 'result.json', 'execution_assessment.json', 'raw.npz', 'config_manifest.json']:
            inputs.append({'path': str((folder/name).relative_to(HERE.parent)),
                           'sha256': hashlib.sha256((folder/name).read_bytes()).hexdigest()})
        with np.load(folder / 'raw.npz') as raw:
            seq, produced, received = raw['seq'], raw['t_ns'], raw['t_ing']
            ids, inverse = np.unique(seq, return_inverse=True)
            first = np.full(len(ids), np.iinfo(np.int64).max, dtype=np.int64)
            np.minimum.at(first, inverse, received)
            # Independently reduce first arrivals, without calling the campaign analyzer.
            event_windows = {}
            for tag, saved in result['streams'].items():
                manifest = json.loads((folder/f'gen-{tag}.json').read_text())
                event_path = folder / manifest['event_records_file']
                digest = hashlib.sha256(event_path.read_bytes()).hexdigest()
                assert digest == manifest['event_records_sha256']
                inputs.append({'path': str(event_path.relative_to(HERE.parent)), 'sha256': digest})
                events = read_events(event_path, manifest)
                sent = events[events['sent_ok'] == 1]
                mask = (ids >= manifest['seq_start']) & (ids < manifest['seq_end'])
                got, arrival = ids[mask], first[mask]
                where = np.searchsorted(sent['seq'], got)
                assert np.array_equal(sent['seq'][where], got)
                times = sent['wall_ns'][where]
                raw_mask = (seq >= manifest['seq_start']) & (seq < manifest['seq_end'])
                raw_where = np.searchsorted(sent['seq'], seq[raw_mask])
                assert np.array_equal(produced[raw_mask], sent['wall_ns'][raw_where])
                assert np.all(arrival >= times)
                counts = [len(sent), len(got), int(raw_mask.sum())-len(got), len(sent)-len(got)]
                keys = ['n_sent_ok', 'n_first_receipts', 'n_duplicate_receipts', 'n_missing_at_cutoff']
                assert counts == [saved[k] for k in keys], (spec['id'], tag, counts)
                start = (result['scheduled_start_ns']+60_000_000_000 if spec['phase']=='E1'
                         else manifest['start_ns']+int(spec['warmup']*1e9))
                end = (result['scheduled_start_ns']+240_000_000_000 if spec['phase']=='E1'
                       else manifest['end_ns']-int(spec['cooldown']*1e9))
                expected = int(((sent['wall_ns']>=start)&(sent['wall_ns']<end)).sum())
                in_window = (times>=start)&(times<end)
                latency = (arrival[in_window]-times[in_window])/1e6
                metric = saved['flood_window' if spec['phase']=='E1' else 'full_window']
                assert expected == metric['n_sent_ok']
                assert expected-len(latency) == metric['n_missing_at_cutoff']
                for q in [50,95,99]:
                    assert np.isclose(np.percentile(latency,q), metric[f'p{q}_ms'], rtol=1e-10)
                assert np.isclose(latency.max(),metric['max_ms'],rtol=1e-10)
                row = dict(position=position, run_id=spec['id'], phase=spec['phase'],
                           variant=spec['variant'], repetition=spec['repetition'], stream=tag,
                           rate=spec['rate'], flood=spec.get('flood',{}).get('rate',0),
                           pause_s=spec.get('fault',{}).get('dur',0),
                           **dict(zip(keys,counts)), window_sent=expected,
                           window_missing=expected-len(latency),
                           p50_ms=metric['p50_ms'], p95_ms=metric['p95_ms'],
                           p99_ms=metric['p99_ms'], max_ms=metric['max_ms'])
                rows.append(row)
                event_windows[tag] = (expected, latency)
                if spec['phase']=='E2-capacity':
                    a, b = manifest['start_ns']+60_000_000_000, manifest['start_ns']+240_000_000_000
                    def backlog(t):
                        return int((sent['wall_ns']<=t).sum()-(arrival<=t).sum())
                    capacity.append(dict(run_id=spec['id'],rate=spec['rate'],repetition=spec['repetition'],
                        first_receipt_eps_60_240=float(((arrival>a)&(arrival<=b)).sum()/180),
                        backlog_60=backlog(a),backlog_240=backlog(b),
                        backlog_300=backlog(manifest['start_ns']+300_000_000_000)))
                if spec['phase']=='E2-outage':
                    ready = result['fault']['ready_ns']
                    pre = sent['seq'][sent['wall_ns']<=ready]
                    missing_pre = len(np.setdiff1d(pre,got,assume_unique=True))
                    assert missing_pre == saved['pre_clearance']['n_missing_at_cutoff']
                    observed_pre = np.isin(got,pre,assume_unique=True)
                    last = max(0,(int(arrival[observed_pre].max())-ready)/1e9)
                    assert np.isclose(last,saved['pre_clearance']['last_observed_s'])
                    # Independent reconstruction on the exact saved one-second grid.
                    grid=np.arange(manifest['start_ns'],max(saved['cutoff_ns'],manifest['end_ns'])+1,10**9,dtype=np.int64)
                    backlog=np.searchsorted(np.sort(sent['wall_ns']),grid,side='right')-np.searchsorted(np.sort(arrival),grid,side='right')
                    fault_start=result['fault']['effective_start_ns']
                    base=float(np.median(backlog[(grid>=fault_start-40*10**9)&(grid<fault_start-10*10**9)]))
                    tolerance=max(50,int(np.ceil(.1*manifest['target_rate'])))
                    eligible=(grid>=ready)&(grid<=manifest['end_ns'])
                    bg=backlog[eligible]; tg=grid[eligible]
                    valid=np.flatnonzero(np.convolve((bg<=base+tolerance).astype(int),np.ones(31,dtype=int),'valid')==31)
                    catch = None if counts[3] or not len(valid) else (int(tg[valid[0]])-ready)/1e9
                    status=('incomplete_at_cutoff' if counts[3] else
                            'observed' if catch is not None else 'censored_before_generator_stop')
                    assert status==saved['catchup']['catchup_status']
                    if catch is not None:
                        assert np.isclose(catch,saved['catchup']['catchup_steady_s'])
                    outages.append(dict(run_id=spec['id'],variant=spec['variant'],rate=spec['rate'],
                        pause_s=spec['fault']['dur'],repetition=spec['repetition'],sent=counts[0],
                        missing=counts[3],missing_pct=100*counts[3]/counts[0],duplicates=counts[2],
                        pre_missing=missing_pre,pre_recovery_s=last if not missing_pre else None,
                        catchup_status=status,catchup_s=catch,baseline=base,tolerance=tolerance,
                        production_after_ready_s=(manifest['end_ns']-ready)/1e9,
                        udp_rcvbuf_errors=sum(x.get('RcvbufErrors',0) for x in result['udp_namespace_counter_deltas'].values())))
            if spec['phase']=='E1':
                for source,tags in [('auth',['auth']),('web',['nginx','flood'])]:
                    n=sum(event_windows[t][0] for t in tags if t in event_windows)
                    lat=np.concatenate([event_windows[t][1] for t in tags if t in event_windows])
                    exposure.append(dict(run_id=spec['id'],variant=spec['variant'],
                        repetition=spec['repetition'],flood=spec['flood']['rate'],source=source,
                        sent=n,missing=n-len(lat),missing_pct=100*(n-len(lat))/n,
                        p95_s=float(np.percentile(lat,95)/1000),max_s=float(lat.max()/1000)))
        runs.append(result)
    assert len(runs)==51 and len(rows)==87 and len(capacity)==6 and len(outages)==21
    csv_write('paper_per_stream.csv',rows)
    csv_write('paper_e1_exposure.csv',exposure)
    csv_write('paper_capacity.csv',capacity)
    csv_write('paper_recovery.csv',outages)
    (HERE/'paper_input_hashes.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (HERE/'paper_validation.json').write_text(json.dumps(dict(runs=51,streams=87,
        independent_counts_and_quantiles='passed',generator_hashes='passed',
        independent_recovery_endpoints='passed',
        total_sent=sum(r['n_sent_ok'] for r in rows),
        total_missing=sum(r['n_missing_at_cutoff'] for r in rows),
        total_duplicates=sum(r['n_duplicate_receipts'] for r in rows)),indent=2)+'\n')
    plt.rcParams.update({'font.size':9,'axes.spines.top':False,'axes.spines.right':False,
                         'pdf.fonttype':42,'ps.fonttype':42})
    variants=['A-sep','A-shared','B-disk','C']
    colors=['#0072B2','#D55E00']
    fig,axes=plt.subplots(2,2,figsize=(10,6),layout='constrained')
    for row,source in enumerate(['auth','web']):
        for j,flood in enumerate([0,6000]):
            for i,v in enumerate(variants):
                group=[r for r in exposure if r['source']==source and r['variant']==v and r['flood']==flood]
                group.sort(key=lambda r:r['repetition'])
                x=i+(j-.5)*.3+np.array([-.045,0,.045])
                for col,key in enumerate(['p95_s','missing_pct']):
                    axes[row,col].scatter(x,[r[key] for r in group],color=colors[j],
                        marker=['o','s'][j],s=26,label=['No flood','+6,000 EPS flood'][j] if i==0 else None)
        axes[row,0].set_yscale('log')
        axes[row,0].set_ylabel(('Authentication' if row==0 else 'Web (normal + flood)')+'\np95 receipt latency (s)')
        axes[row,1].set_ylabel('Missing at cutoff (%)')
        for ax in axes[row]:
            ax.set_xticks(range(4),variants)
            ax.grid(axis='y',alpha=.2)
    axes[0,0].legend(frameon=False)
    fig.suptitle('E1: events produced during seconds 60–240; each point is one run\nLatency excludes missing IDs; web includes both web generators')
    save(fig,'prototype_e1')
    fig,axes=plt.subplots(1,2,figsize=(10,3.7),layout='constrained')
    for j,rate in enumerate([4000,6000]):
        for r in [r for r in capacity if r['rate']==rate]:
            data=np.genfromtxt(NEW_RESULTS/r['run_id']/'backlog-nginx.csv',delimiter=',',names=True)
            use=data['seconds_from_start']<=300
            axes[0].plot(data['seconds_from_start'][use],data['backlog_to_request_receipt'][use]/1000,
                color=colors[j],linestyle=['-', '--', ':'][r['repetition']-1],
                label=f"{rate:,} EPS, r{r['repetition']}")
            axes[1].scatter(j+(r['repetition']-2)*.06,r['first_receipt_eps_60_240'],color=colors[j])
        axes[1].hlines(rate,j-.2,j+.2,color=colors[j],linestyle='--')
    axes[0].set(xlabel='Seconds from generation start',ylabel='Backlog to receipt (thousand IDs)')
    axes[0].legend(frameon=False,ncol=2,fontsize=7)
    axes[1].set(xticks=[0,1],xticklabels=['4,000 EPS','6,000 EPS'],ylabel='First receipts/s, seconds 60–240',ylim=(0,6500))
    axes[1].set_title('Dashed lines: offered rate')
    fig.suptitle('E2 capacity: all IDs eventually observed; backlog still grows at 6,000 EPS')
    save(fig,'prototype_capacity')
    conditions=[('A-sep',500,60),('A-sep',500,300),('A-sep',500,600),('A-sep',2000,600),
                ('B-disk',500,600),('B-disk',2000,600),('C',500,600)]
    fig,axes=plt.subplots(1,3,figsize=(12,4.5),layout='constrained',sharey=True)
    for i,condition in enumerate(conditions):
        for r in [r for r in outages if (r['variant'],r['rate'],r['pause_s'])==condition]:
            y=i+(r['repetition']-2)*.16
            pre=r['pre_recovery_s']
            if pre is not None: axes[0].scatter(pre,y,color='#0072B2',s=24)
            else: axes[0].text(4,y,'incomplete',fontsize=7,va='center',color='#D55E00')
            if r['catchup_s'] is not None: axes[1].scatter(r['catchup_s'],y,color='#0072B2',s=24)
            elif r['catchup_status']=='incomplete_at_cutoff':
                axes[1].text(4,y,'missing IDs',fontsize=7,va='center',color='#D55E00')
            else:
                # An open symbol marks the observation end, not a recovery time.
                axes[1].scatter(r['production_after_ready_s'],y,marker='>',facecolors='none',edgecolors='#D55E00',s=40)
            axes[2].scatter(r['missing_pct'],y,color='#D55E00',s=24)
    axes[0].set_yticks(range(7),[f'{v}, {rate:,} EPS, {pause}s' for v,rate,pause in conditions])
    axes[0].invert_yaxis()
    for ax in axes[:2]:
        ax.set_xscale('log'); ax.set_xlim(3,1200)
        ax.set_xlabel('Seconds after backend readiness'); ax.grid(axis='x',alpha=.2)
    axes[0].set_title('Pre-readiness cohort completed')
    axes[1].set_title('Return to baseline backlog\n▷ observation ends; criterion unobserved')
    axes[2].set(xlabel='Missing at cutoff (%)',title='All successfully sent IDs',xlim=(-.15,4.6))
    fig.suptitle('E2 outage: three observations per condition; incomplete endpoints are not zero')
    save(fig,'prototype_recovery')
    print('Validated 51 runs / 87 streams, generator hashes, counts, quantiles and 21 recovery endpoints; exported 4 CSVs and 3 figure prototypes.')


if __name__=='__main__':
    main()
