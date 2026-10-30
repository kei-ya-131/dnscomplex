#!/usr/bin/env python3
"""Linux root regression for exact readiness wildcards using actual nft JSON.

All nft state lives in a private network namespace; runtime is read only.
"""
import argparse
import pathlib
import subprocess
import sys

p=argparse.ArgumentParser()
p.add_argument('--runtime-script',type=pathlib.Path,required=True)
p.add_argument('--isolated',action='store_true')
a=p.parse_args()
if not a.isolated:
    raise SystemExit(subprocess.run(['unshare','--net',sys.executable,str(pathlib.Path(__file__).resolve()),'--isolated','--runtime-script',str(a.runtime_script.resolve())],timeout=30).returncode)

def nft(text):
    subprocess.run(['nft','-f','-'],input=text,text=True,check=True,capture_output=True,timeout=3)
def function(command,mode='xray'):
    return subprocess.run(['bash','-c','source "$1"; AI_EGRESS_MODE=$2; CN_EGRESS_MODE=$2; '+command,'_',str(a.runtime_script),mode],capture_output=True,text=True,timeout=3)
def expect(profile,mode,want):
    r=function('profile_egress_gate_is_open '+profile,mode)
    got=r.returncode==0
    assert got==want,(profile,mode,want,r.returncode,r.stderr)
    print(profile,mode,'open='+str(got),'PASS',flush=True)

nft('add table inet dnscomplex\n'+''.join('add set inet dnscomplex '+name+' { type '+family+'_addr; flags interval; }\n' for name,family in [('ai_ready4','ipv4'),('ai_ready6','ipv6'),('cn_ready4','ipv4'),('cn_ready6','ipv6')]))
for mode in ['ipsec','xray']:expect('ai',mode,False)
r=function('profile_egress_gate_open ai');assert r.returncode==0,r.stderr
expect('ai','xray',True);expect('cn','xray',False)
nft('flush set inet dnscomplex ai_ready6\n')
expect('ai','xray',False);expect('ai','ipsec',True)
# Same conditional used by watchdog: missing IPv6 must trigger atomic repair.
r=function('profile_egress_gate_is_open ai || profile_egress_gate_open ai');assert r.returncode==0,r.stderr
expect('ai','xray',True)
nft('flush set inet dnscomplex ai_ready4\nadd element inet dnscomplex ai_ready4 { 0.0.0.0/1 }\n')
expect('ai','xray',False);expect('ai','ipsec',False)
r=function('profile_egress_gate_open ai');assert r.returncode==0,r.stderr
nft('flush set inet dnscomplex ai_ready6\nadd element inet dnscomplex ai_ready6 { ::/1 }\n')
expect('ai','xray',False);expect('ai','ipsec',True)
r=function('profile_egress_gate_clear ai');assert r.returncode==0,r.stderr
expect('ai','xray',False);expect('ai','ipsec',False)
r=function('profile_egress_gate_open cn','ipsec');assert r.returncode==0,r.stderr
expect('cn','ipsec',True);expect('cn','xray',False)
print('PASS: actual nft readiness wildcard/partial/empty, family requirements, atomic open/clear and IPv6 repair; isolated only')
