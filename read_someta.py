import json
import pandas as pd

def _read_cpu(lineinfo):
    df = pd.DataFrame(lineinfo['data'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    xd = pd.DataFrame()
    for i in range(len(df)):
        row = df.iloc[i]
        idlevals = pd.DataFrame(row['cpuidle'], index=[i])
        xd = pd.concat([xd, idlevals])
    xd.index = df['timestamp']
    return xd
    
def _read_mem(lineinfo):
    df = pd.DataFrame(lineinfo['data'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

def _read_netstat(lineinfo):
    df = pd.DataFrame(lineinfo['data'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    xd = pd.DataFrame()
    for i in range(len(df)):
        row = df.iloc[i]
        intfvals = pd.DataFrame.from_dict(row['netstat'], orient='columns')
        intfvals = intfvals.T
        intfvals.index = [row.timestamp]
        xd = pd.concat([xd, intfvals])
    return xd

def _read_io(lineinfo):
    df = pd.DataFrame(lineinfo['data'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    xd = pd.DataFrame()
    for i in range(len(df)):
        row = df.iloc[i]
        intfvals = pd.DataFrame.from_dict(row['counters'], orient='columns')
        intfvals = intfvals.T
        intfvals.index = [row.timestamp]
        xd = pd.concat([xd, intfvals])
    return xd

def _read_rtt(lineinfo):
    df = pd.DataFrame(lineinfo['probes'])
    df['sendtime'] = pd.to_datetime(df['sendtime'], errors='coerce')
    df['wiresend'] = pd.to_datetime(df['wiresend'], errors='coerce')
    df['wirerecv'] = pd.to_datetime(df['wirerecv'], errors='coerce')
    return df

def read_someta(filename):
    dfdict = {}
    with open(filename) as infile:
        for line in infile:
            lineinfo = json.loads(line)
            # print(lineinfo)
            name = lineinfo['name']
            dfdata = None
            if name == 'someta':
                dfdict[name] = lineinfo
            else:
                fn = globals().get('_read_{}'.format(name), None)
                if fn is None:
                    print("Don't know how to handle {} metadata".format(name))
                    print("Ignoring and continuing...")
                    continue
                    
                dfdata = fn(lineinfo)
                if name not in dfdict:
                    dfdict[name] = dfdata
                else:
                    dfdict[name] = pd.concat([dfdict[name], dfdata])
    return dfdict
