/**
 * The managed launcher the native OS manager actually starts.
 *
 * This file *generates* that launcher. The output is written into the managed
 * directory and run by Task Scheduler, systemd or launchd with no repository,
 * no `node_modules` and no TypeScript flag, so it has to be self-contained.
 *
 * WHAT CHANGED IN v2, AND WHY IT HAD TO
 *
 * The Phase 19 launcher read `install.json` once at startup and then supervised
 * one release for the life of the login session. That is fine until the
 * metadata is a transaction: a launcher holding a stale decision cannot promote
 * a candidate, cannot roll one back, and cannot resume either after a reboot.
 * So v2 re-reads and re-validates the install, and re-hashes the release it is
 * about to start, before *every* launch.
 *
 * MIGRATION SAFETY
 *
 * v2 is installed while v1 is still running, and v1 keeps supervising the 0.6
 * Agent it already started. Nothing tries to talk to it. The switch happens
 * when the existing OS registration next starts the launcher -- the same
 * command line, the same task, the same unit -- which by then is v2 on disk.
 * The registration is never rewritten to change Agent version.
 *
 * That is also why v2 must be able to run BOTH Agents. The command line it
 * builds (`run --url --config`) is identical in 0.6 and 0.7, and the extra
 * trial arguments are added only for a candidate on trial. Rolling back to 0.6
 * keeps launcher v2; it never regenerates a launcher from the older Agent,
 * which would undo the transaction support and strand the node again.
 */
import {
  AGENT_EXIT,
  AUTOSTART_CRASH_LIMIT,
  AUTOSTART_CRASH_WINDOW_MS,
  AUTOSTART_LOG_FILES,
  AUTOSTART_LOG_MAX_BYTES,
  AUTOSTART_RESTART_DELAY_MS,
  UPGRADE_QUARANTINE_LIMIT,
  UPGRADE_READINESS_NOTICE_MS,
  UPGRADE_TRIAL_ATTEMPT_LIMIT,
} from './managed-upgrade.ts';
import { NODE_PROTOCOL_VERSION } from '../lib/nodes.ts';

/** How often a trial checks for its readiness proof. */
export const UPGRADE_READINESS_POLL_MS = 1_000;

export function buildManagedLauncherSource(): string {
  // Kept self-contained: the installed launcher must run without this repository.
  return `import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFile, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
const MAX=${AUTOSTART_LOG_MAX_BYTES}, FILES=${AUTOSTART_LOG_FILES}, LIMIT=${AUTOSTART_CRASH_LIMIT}, WINDOW=${AUTOSTART_CRASH_WINDOW_MS}, RETRY_DELAY=${AUTOSTART_RESTART_DELAY_MS};
const TRIAL_LIMIT=${UPGRADE_TRIAL_ATTEMPT_LIMIT}, NOTICE=${UPGRADE_READINESS_NOTICE_MS}, QUARANTINE=${UPGRADE_QUARANTINE_LIMIT}, READY_POLL=${UPGRADE_READINESS_POLL_MS};
const EXIT={ok:${AGENT_EXIT.clean},already:${AGENT_EXIT.alreadyRunning},auth:${AGENT_EXIT.authorizationRejected},credential:${AGENT_EXIT.credentialInvalid},runtime:${AGENT_EXIT.unsupportedRuntime},controlled:${AGENT_EXIT.controlledShutdown}};
const terminal=new Set([EXIT.already,EXIT.auth,EXIT.credential,EXIT.runtime,EXIT.controlled]);
const NULL_TX='0'.repeat(32);
const hash=(value)=>createHash('sha256').update(value).digest('hex');
const redact=(value)=>value.replace(/\\bAuthorization\\s*:\\s*[^\\r\\n]+/giu,'Authorization: [REDACTED]').replace(/\\b(cookie|session)\\s*[=:]\\s*[^\\s;]+/giu,'$1=[REDACTED]').replace(/\\bYSD_NODE_AGENT_KEY\\s*=\\s*[^\\s]+/giu,'YSD_NODE_AGENT_KEY=[REDACTED]').replace(/\\bysdp_[A-Za-z0-9_-]{16,}/gu,'[REDACTED]').replace(/\\bnode_[A-Za-z0-9_.-]{20,}/gu,'[REDACTED]');
const bounded=(value)=>{const bytes=Buffer.from(value);if(bytes.length<=MAX)return value;let start=bytes.length-MAX;while(start<bytes.length&&(bytes[start]&0xc0)===0x80)start++;return bytes.subarray(start).toString('utf8');};
const states=new Set(['enabled','disabled','manager_missing','agent_missing','node_runtime_missing','registration_invalid','upgrade_required','credential_key_unavailable','restart_limited','authorization_rejected','already_running','stopped','starting']);
const managers=new Set(['windows-task-scheduler','systemd-user','launchagent']);
const upgradeStates=new Set(['idle','staged','trial','rollback_pending','blocked']);
const absolute=(value)=>typeof value==='string'&&path.isAbsolute(value)&&!/[\\u0000\\r\\n]/u.test(value);
const semver=(value)=>typeof value==='string'&&/^(0|[1-9]\\d{0,5})\\.(0|[1-9]\\d{0,5})\\.(0|[1-9]\\d{0,5})$/u.test(value);
const release=(value)=>!!value&&semver(value.version)&&absolute(value.releasePath)&&/^[a-f0-9]{64}$/u.test(value.releaseHash);
const upgradeValid=(value)=>!!value&&upgradeStates.has(value.state)&&/^[a-f0-9]{32}$/u.test(value.transactionId)&&Number.isSafeInteger(value.generation)&&value.generation>=0&&Number.isSafeInteger(value.attempts)&&value.attempts>=0&&value.attempts<=TRIAL_LIMIT&&(value.candidate===null||release(value.candidate))&&Array.isArray(value.quarantine)&&value.quarantine.length<=QUARANTINE&&!((value.state==='trial'||value.state==='staged')&&value.candidate===null);
const optionalUpgrade=(value)=>value===undefined||value===null||upgradeValid(value);
const optionalRelease=(value)=>value===undefined||value===null||release(value);
const validInstall=(value)=>value&&value.version===1&&/^[a-f0-9]{16}$/u.test(value.instanceId)&&typeof value.agentVersion==='string'&&value.protocolVersion===${NODE_PROTOCOL_VERSION}&&managers.has(value.manager)&&value.scope==='user-session'&&absolute(value.nodeExecutable)&&absolute(value.releasePath)&&absolute(value.launcherPath)&&absolute(value.credentialPath)&&absolute(value.agentHome)&&absolute(value.workingDirectory)&&/^[a-f0-9]{64}$/u.test(value.releaseHash)&&/^[a-f0-9]{64}$/u.test(value.launcherHash)&&/^[a-f0-9]{64}$/u.test(value.registrationFingerprint)&&typeof value.origin==='string'&&optionalUpgrade(value.upgrade)&&optionalRelease(value.previousRelease);
const validStatus=(value)=>value&&value.version===1&&typeof value.enabled==='boolean'&&managers.has(value.manager)&&value.scope==='user-session'&&states.has(value.state)&&typeof value.agentVersion==='string'&&(value.lastStartAt===null||Number.isSafeInteger(value.lastStartAt))&&(value.lastExitAt===null||Number.isSafeInteger(value.lastExitAt))&&Number.isSafeInteger(value.restartCount)&&value.restartCount>=0&&value.restartCount<=LIMIT&&(value.registrationFingerprint===null||/^[a-f0-9]{64}$/u.test(value.registrationFingerprint))&&Array.isArray(value.crashFailures)&&value.crashFailures.length<=LIMIT&&value.crashFailures.every((entry)=>Number.isSafeInteger(entry)&&entry>=0);
const atomic=async(file,value)=>{const temporary=path.join(path.dirname(file),'.'+path.basename(file)+'.'+process.pid+'.tmp');await rm(temporary,{force:true});const handle=await open(temporary,'wx',0o600);try{await handle.writeFile(JSON.stringify(value)+'\\n','utf8');await handle.sync();}finally{await handle.close();}await rename(temporary,file);};
const log=async(directory,value)=>{await mkdir(directory,{recursive:true,mode:0o700});const safe=bounded(redact(value)),current=path.join(directory,'agent.log');let size=0;try{size=(await stat(current)).size;}catch{}if(size+Buffer.byteLength(safe)>MAX){await rm(path.join(directory,'agent.'+(FILES-1)+'.log'),{force:true});for(let index=FILES-2;index>=1;index--)try{await rename(path.join(directory,'agent.'+index+'.log'),path.join(directory,'agent.'+(index+1)+'.log'));}catch{}try{await rename(current,path.join(directory,'agent.1.log'));}catch{}}await appendFile(current,safe,{encoding:'utf8',mode:0o600});};
let logQueue=Promise.resolve();const queueLog=(directory,value)=>{logQueue=logQueue.then(()=>log(directory,value)).catch(()=>{});return logQueue;};
const installPath=process.argv[process.argv.indexOf('--install')+1];
if(!installPath||!path.isAbsolute(installPath)) process.exit(EXIT.credential);
const root=path.dirname(installPath), statusPath=path.join(root,'status.json'), logDirectory=path.join(root,'logs'), readinessPath=path.join(root,'readiness.json'), releaseRoot=path.join(root,'releases');
const idle=(now)=>({state:'idle',transactionId:NULL_TX,generation:0,candidate:null,attempts:0,reason:null,quarantine:[],updatedAt:now});
const upgradeOf=(value)=>upgradeValid(value.upgrade)?value.upgrade:idle(0);
const currentOf=(value)=>({version:value.agentVersion,releasePath:value.releasePath,releaseHash:value.releaseHash});
const select=(value)=>{const plan=upgradeOf(value);if(plan.state==='blocked')return null;if(plan.state==='trial'&&plan.candidate)return{release:plan.candidate,trial:true};return{release:currentOf(value),trial:false};};
const quarantine=(plan,entry)=>({...plan,quarantine:plan.quarantine.filter((row)=>row.releaseHash!==entry.releaseHash).concat(entry).slice(-QUARANTINE)});
const rollback=(value,reason,now)=>{const plan=upgradeOf(value),failed=plan.candidate,kept=failed?quarantine(plan,{version:failed.version,releaseHash:failed.releaseHash,reason}):plan;return{...value,upgrade:{...kept,state:'idle',candidate:null,attempts:0,reason,generation:plan.generation+1,updatedAt:now},updatedAt:now};};
const promote=(value,now)=>{const plan=upgradeOf(value),candidate=plan.candidate;if(!candidate)return value;const previous=currentOf(value);return{...value,agentVersion:candidate.version,releasePath:candidate.releasePath,releaseHash:candidate.releaseHash,previousVersion:previous.version,previousRelease:previous,upgrade:{...plan,state:'idle',candidate:null,attempts:0,reason:null,updatedAt:now},updatedAt:now};};
const markerValid=(value,plan)=>!!value&&!!plan.candidate&&value.version===1&&value.transactionId===plan.transactionId&&value.generation===plan.generation&&value.agentVersion===plan.candidate.version&&Number.isSafeInteger(value.acceptedAt)&&value.acceptedAt>0;
const trialOutcome=(code,attempts,stopped)=>{if(stopped)return{action:'hold',reason:null};if(code===EXIT.auth)return{action:'block',reason:'authorization_rejected'};if(code===EXIT.credential)return{action:'block',reason:'credential_invalid'};if(code===EXIT.already)return{action:'hold',reason:'ownership_conflict'};if(code===EXIT.controlled||code===EXIT.ok)return{action:'hold',reason:null};if(code===EXIT.runtime)return{action:'rollback',reason:'candidate_incompatible'};return attempts>=TRIAL_LIMIT?{action:'rollback',reason:'candidate_start_failed'}:{action:'retry',reason:'candidate_start_failed'};};
const loadInstall=async()=>{const value=JSON.parse(await readFile(installPath,'utf8'));if(!validInstall(value))throw new Error('install_invalid');return value;};
let install=null,status=null;
try{install=await loadInstall();}catch{await log(logDirectory,'launcher validation failed\\n');try{const raw=JSON.parse(await readFile(installPath,'utf8'));await atomic(statusPath,{version:1,enabled:true,manager:managers.has(raw.manager)?raw.manager:'windows-task-scheduler',scope:'user-session',state:'registration_invalid',agentVersion:typeof raw.agentVersion==='string'?raw.agentVersion:'unknown',lastStartAt:null,lastExitAt:Date.now(),restartCount:0,registrationFingerprint:/^[a-f0-9]{64}$/u.test(raw.registrationFingerprint)?raw.registrationFingerprint:null,crashFailures:[]});}catch{}process.exit(0);}
try{status=JSON.parse(await readFile(statusPath,'utf8'));}catch{}
if(!validStatus(status))status={version:1,enabled:true,manager:install.manager,scope:'user-session',state:'starting',agentVersion:install.agentVersion,lastStartAt:null,lastExitAt:null,restartCount:0,registrationFingerprint:install.registrationFingerprint,crashFailures:[]};
const childEnv=Object.fromEntries(Object.entries(process.env).filter(([key])=>!['YSD_NODE_AGENT_KEY','YSD_NODE_PAIRING_CODE'].includes(key)));childEnv.YSD_NODE_AGENT_HOME=install.agentHome;
let controlled=false,child=null;for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{controlled=true;try{child?.kill(signal);}catch{}});
const sleep=(milliseconds)=>new Promise((resolve)=>setTimeout(resolve,milliseconds));
const publish=async(patch)=>{status={...status,...patch};await atomic(statusPath,status);};
while(!controlled){
try{install=await loadInstall();}catch{await queueLog(logDirectory,'launcher validation failed\\n');await publish({state:'registration_invalid',lastExitAt:Date.now()});break;}
let plan=upgradeOf(install);
if(plan.state==='rollback_pending'){const reason=plan.reason||'candidate_start_failed';const failed=plan.candidate;install=rollback(install,reason,Date.now());await atomic(installPath,install);if(failed){const directory=path.dirname(failed.releasePath);if(path.dirname(directory)===releaseRoot)await rm(directory,{recursive:true,force:true});}await queueLog(logDirectory,'previous Agent restored version='+install.agentVersion+'\\n');plan=upgradeOf(install);await publish({agentVersion:install.agentVersion,upgrade:{state:'upgrade_rolled_back',reason,transactionId:plan.transactionId,candidateVersion:failed?failed.version:null}});}
const selection=select(install);
if(!selection){await publish({state:plan.reason==='credential_invalid'?'credential_key_unavailable':'authorization_rejected',lastExitAt:Date.now(),upgrade:{state:'upgrade_blocked',reason:plan.reason,transactionId:plan.transactionId,candidateVersion:plan.candidate?plan.candidate.version:null}});break;}
let nodeInfo=null;try{nodeInfo=await stat(install.nodeExecutable);}catch{}
if(!nodeInfo||!nodeInfo.isFile()){await publish({state:'node_runtime_missing',lastExitAt:Date.now()});break;}
let bytes=null;try{bytes=await readFile(selection.release.releasePath);}catch{}
const mismatch=bytes!==null&&hash(bytes)!==selection.release.releaseHash;
if(bytes===null||mismatch){if(selection.trial){const reason=mismatch?'candidate_hash_mismatch':'candidate_unreadable';install=rollback(install,reason,Date.now());await atomic(installPath,install);await queueLog(logDirectory,'candidate failed reason='+reason+'\\n');await publish({upgrade:{state:'upgrade_rolled_back',reason,transactionId:plan.transactionId,candidateVersion:selection.release.version}});continue;}await publish({state:bytes===null?'agent_missing':'registration_invalid',lastExitAt:Date.now()});break;}
const now=Date.now();
const failures=(Array.isArray(status.crashFailures)?status.crashFailures:[]).filter((time)=>Number.isSafeInteger(time)&&time>=now-WINDOW&&time<=now);
if(!selection.trial&&failures.length>=LIMIT){await publish({state:'restart_limited',restartCount:failures.length,crashFailures:failures});break;}
let args=[selection.release.releasePath,'run','--url',install.origin,'--config',install.credentialPath];
const startPatch={state:'starting',lastStartAt:now,agentVersion:selection.release.version,restartCount:failures.length,crashFailures:failures};
if(selection.trial){install={...install,upgrade:{...plan,attempts:plan.attempts+1,updatedAt:now},updatedAt:now};await atomic(installPath,install);plan=upgradeOf(install);await rm(readinessPath,{force:true});args=args.concat(['--managed-trial',plan.transactionId,'--managed-generation',String(plan.generation)]);await queueLog(logDirectory,'candidate trial started version='+selection.release.version+' attempt='+plan.attempts+'\\n');startPatch.upgrade={state:'upgrade_trial',reason:null,transactionId:plan.transactionId,candidateVersion:selection.release.version};}
await publish(startPatch);
let promoted=false,watch=null;
const outcome=await new Promise((resolve)=>{
child=spawn(install.nodeExecutable,args,{cwd:install.workingDirectory,shell:false,windowsHide:true,env:childEnv,stdio:['ignore','pipe','pipe']});
child.stdout.on('data',(chunk)=>void queueLog(logDirectory,String(chunk)));
child.stderr.on('data',(chunk)=>void queueLog(logDirectory,String(chunk)));
if(selection.trial){const started=Date.now();let noticed=false;watch=setInterval(()=>{void (async()=>{if(promoted)return;let marker=null;try{marker=JSON.parse(await readFile(readinessPath,'utf8'));}catch{}
if(markerValid(marker,plan)){promoted=true;if(watch){clearInterval(watch);watch=null;}install=promote(install,Date.now());await atomic(installPath,install);await rm(readinessPath,{force:true});await queueLog(logDirectory,'candidate heartbeat accepted; candidate promoted version='+install.agentVersion+'\\n');status={...status,agentVersion:install.agentVersion,upgrade:{state:'upgrade_succeeded',reason:null,transactionId:plan.transactionId,candidateVersion:install.agentVersion}};await atomic(statusPath,status);}
else if(!noticed&&Date.now()-started>=NOTICE){noticed=true;status={...status,upgrade:{state:'upgrade_waiting_for_network',reason:'network_unavailable',transactionId:plan.transactionId,candidateVersion:selection.release.version}};await atomic(statusPath,status);}})();},READY_POLL);}
let finished=false;
child.once('error',async()=>{if(finished)return;finished=true;await queueLog(logDirectory,'agent spawn failed\\n');resolve({code:null});});
child.once('exit',async(code)=>{if(finished)return;finished=true;await logQueue;resolve({code});});});
if(watch){clearInterval(watch);watch=null;}
child=null;const ended=Date.now(),code=outcome.code;
await queueLog(logDirectory,'agent exited code='+(Number.isInteger(code)?code:'spawn_error')+'\\n');
if(selection.trial&&!promoted){
const decision=trialOutcome(code,upgradeOf(install).attempts,controlled);
const candidateVersion=selection.release.version;
if(decision.action==='block'){install={...install,upgrade:{...upgradeOf(install),state:'blocked',reason:decision.reason,updatedAt:ended},updatedAt:ended};await atomic(installPath,install);await queueLog(logDirectory,'candidate failed reason='+decision.reason+'\\n');await publish({state:decision.reason==='credential_invalid'?'credential_key_unavailable':'authorization_rejected',lastExitAt:ended,upgrade:{state:'upgrade_blocked',reason:decision.reason,transactionId:plan.transactionId,candidateVersion}});break;}
if(decision.action==='rollback'){install={...install,upgrade:{...upgradeOf(install),state:'rollback_pending',reason:decision.reason,updatedAt:ended},updatedAt:ended};await atomic(installPath,install);const failed=plan.candidate;install=rollback(install,decision.reason,Date.now());await atomic(installPath,install);if(failed){const directory=path.dirname(failed.releasePath);if(path.dirname(directory)===releaseRoot)await rm(directory,{recursive:true,force:true});}await queueLog(logDirectory,'candidate failed reason='+decision.reason+'; previous Agent restored version='+install.agentVersion+'\\n');await publish({state:'stopped',lastExitAt:ended,agentVersion:install.agentVersion,upgrade:{state:'upgrade_rolled_back',reason:decision.reason,transactionId:plan.transactionId,candidateVersion}});await sleep(RETRY_DELAY);continue;}
if(decision.action==='hold'){await publish({state:code===EXIT.already?'already_running':'stopped',lastExitAt:ended});break;}
await publish({state:'stopped',lastExitAt:ended});await sleep(RETRY_DELAY);continue;}
if(code===EXIT.auth){await publish({state:'authorization_rejected',lastExitAt:ended});break;}
if(code===EXIT.already){await publish({state:'already_running',lastExitAt:ended});break;}
if(code===EXIT.ok||controlled||terminal.has(code)){await publish({state:'stopped',lastExitAt:ended});break;}
const next=failures.concat(ended).slice(-LIMIT),retry=next.length<LIMIT;
await publish({state:retry?'stopped':'restart_limited',lastExitAt:ended,restartCount:next.length,crashFailures:next});
if(!retry)break;
await sleep(RETRY_DELAY);}
process.exit(0);
`;
}
