#!/usr/bin/env python3
import argparse, re, json, csv
from collections import defaultdict, Counter
from datetime import datetime

# regex covers common combined log format
LOG_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]+)" (?P<code>\d{3}) (?P<size>\S+)( "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')

def parse_line(line):
    m = LOG_RE.match(line)
    if not m:
        return None
    return {
        'ip': m.group('ip'),
        'time': m.group('time'),
        'method': m.group('method'),
        'path': m.group('path'),
        'code': int(m.group('code')),
        'size': m.group('size'),
        'ref': m.group('ref') or '',
        'ua': m.group('ua') or '',
    }

def analyze(file_path, thresh_404=50, thresh_5xx=10, top_n=20):
    ips_404 = Counter()
    ips_5xx = Counter()
    ips_total = Counter()
    path_counter = Counter()
    code_counter = Counter()
    total = 0
    with open(file_path,'r',encoding='utf-8',errors='ignore') as f:
        for line in f:
            parsed = parse_line(line)
            if not parsed: 
                continue
            total += 1
            ip = parsed['ip']; code = parsed['code']; path = parsed['path']
            ips_total[ip] += 1
            path_counter[path] += 1
            code_counter[code] += 1
            if code == 404:
                ips_404[ip] += 1
            if 500 <= code < 600:
                ips_5xx[ip] += 1
    # build report
    top_ips = ips_total.most_common(top_n)
    top_paths = path_counter.most_common(top_n)
    top_codes = sorted(code_counter.items(), key=lambda x:-x[1])
    suspicious = []
    for ip in set(list(ips_404.keys()) + list(ips_5xx.keys())):
        if ips_404.get(ip,0) >= thresh_404 or ips_5xx.get(ip,0) >= thresh_5xx:
            suspicious.append({
                'ip': ip,
                '404_count': ips_404.get(ip,0),
                '5xx_count': ips_5xx.get(ip,0),
                'total_requests': ips_total.get(ip,0)
            })
    report = {
        'analyzed_file': file_path,
        'total_lines': total,
        'top_ips': top_ips,
        'top_paths': top_paths,
        'top_status_codes': top_codes,
        'suspicious': suspicious,
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'thresholds': {'404': thresh_404, '5xx': thresh_5xx}
    }
    return report

def save_json(report, out):
    with open(out,'w',encoding='utf-8') as f:
        json.dump(report, f, indent=2)

def save_csv_top_paths(report, out):
    with open(out,'w',encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        w.writerow(['path','count'])
        for p,c in report['top_paths']:
            w.writerow([p,c])

def main():
    p = argparse.ArgumentParser(description='LogSentry - analyze web logs and detect suspicious IPs')
    p.add_argument('logfile')
    p.add_argument('--404-thresh', type=int, default=50)
    p.add_argument('--5xx-thresh', type=int, default=10)
    p.add_argument('--json', help='save json report')
    p.add_argument('--csv-paths', help='save top paths CSV')
    args = p.parse_args()
    report = analyze(args.logfile, args._get_kwargs()[0][1] if False else args.__dict__['404_thresh'] if False else args.__dict__['404-thresh'] if False else args.__dict__.get('404_thresh', args.__dict__['404-thresh']))
    # the above mess of introspection fallback: simplify by pulling explicit names
    # fix: use direct
    report = analyze(args.logfile, thresh_404=args.__dict__['404-thresh'], thresh_5xx=args.__dict__['5xx-thresh'])
    print('Analyzed:', report['analyzed_file'])
    print('Total lines:', report['total_lines'])
    print('Top IPs:')
    for ip,c in report['top_ips'][:10]:
        print(ip, c)
    print('Top paths:')
    for path,c in report['top_paths'][:10]:
        print(path, c)
    print('Suspicious IPs (thresholds):', report['thresholds'])
    for s in report['suspicious']:
        print(s['ip'], '404=', s['404_count'], '5xx=', s['5xx_count'], 'total=', s['total_requests'])
    if args.json:
        save_json(report, args.json)
        print('Saved JSON report to', args.json)
    if args.csv_paths:
        save_csv_top_paths(report, args.csv_paths)
        print('Saved top paths CSV to', args.csv_paths)

if __name__ == '__main__':
    main()

