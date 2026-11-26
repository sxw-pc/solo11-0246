import argparse,json
from pathlib import Path
from .store import connect,execute,replay,rows

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['ownership','certificate','cutover','san_retirement','retirement','demo','report','replay']);p.add_argument('--db',required=True);p.add_argument('--fixture');a=p.parse_args()
    if a.command=='replay':
        result=replay(a.db)
    else:
        db=connect(a.db)
        if a.command=='report':result=rows(db,'SELECT * FROM events ORDER BY seq')
        elif a.command=='demo':
            result=[]
            for name in ['ownership','certificate','cutover']:
                for suffix in ['normal','failure']:
                    steps=json.loads((Path('fixtures')/f'{name}_{suffix}.json').read_text(encoding='utf-8'))
                    result.extend(execute(db,step.get('subsystem',name),step) for step in steps)
        else:
            if not a.fixture:p.error('--fixture required')
            steps=json.loads(Path(a.fixture).read_text(encoding='utf-8'))
            result=[execute(db,step.get('subsystem',a.command),step) for step in steps]
        db.close()
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if a.command=='replay' and not result['verified']:raise SystemExit(2)

if __name__=='__main__':main()
