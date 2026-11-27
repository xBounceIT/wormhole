import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { validSharedHBANetworks } from '../electron/vault-shared-setup-contract.ts';
import { vaultFields, vaultID, vaultRecord } from '../electron/vault-contract.ts';

test('protected setup screen clears credentials and separates recovery display from confirmation', async (t) => {
  const source = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-shared-setup.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const recoverySource = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-admin-recovery-screen.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const backupSource = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-shared-backup-screen.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const restoreSource = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-shared-restore-screen.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const resetIssueSource = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-shared-account-reset-screen.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const resetQueueSource = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-shared-account-reset-queue.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const administrationSource = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-shared-administration.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const slotSources = await Promise.all(
    ['../electron/vault-shared-admin-inventory.ts', '../src/vault-shared-create-slot.ts'].map(
      async (path) =>
        stripTypeScriptTypes(await readFile(new URL(path, import.meta.url), 'utf8'))
          .replace(/^import .*?;\s*/gms, '')
          .replace(/^export /gm, ''),
    ),
  );
  const suspensionInventorySource = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-account-suspension.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const groupSource = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-shared-group-administration.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const grantSource = stripTypeScriptTypes(
    await readFile(new URL('../src/vault-shared-grant-administration.ts', import.meta.url), 'utf8'),
  )
    .replace(/^import .*?;\s*/gms, '')
    .replace(/^export /gm, '');
  const directory = await mkdtemp(join(tmpdir(), 'wormhole-setup-screen-'));
  try {
    const renderer = `
let failKeyGeneration=false;
let failRecoveryDisplay=false;
${validSharedHBANetworks.toString()}
function wipeSharedSetupRequest(value){
  for(const entry of Object.values(value ?? {})) if(entry instanceof Uint8Array) entry.fill(0);
}
async function createRecoveryRecipient(){
  if(failKeyGeneration) throw Error('internal crypto diagnostic');
  return {
    publicKey:new Uint8Array(32),
    async open(){if(failRecoveryDisplay)throw Error('private');return new TextEncoder().encode('WHREC1-'+Array(11).fill('ABCDE').join('-')+'-ABC')},
    dispose(){this.publicKey.fill(0)},
  };
}
${source}
${recoverySource}
${backupSource}
${restoreSource}
const resetWorkspace='11111111-1111-4111-8111-111111111111';
let displayMode='',resetKeyDisposed=0;
function enrollmentID(value){return value===resetWorkspace;}
function enrollmentBytes(value){return value==='public-fixture'?new Uint8Array(32).fill(9):undefined;}
function parseSharedAccountResetIssue(value){return value?.status?value:undefined;}
function parseAccountResetTargetPage(value){return value?.status?value:undefined;}
function parseAccountResetMarkResult(value){return value?.status?value:undefined;}
function accountResetDisplayEnvelope(){}
async function createVaultDisplayRecipient(domain,[workspace,request,login]){
  if(domain!=='wormhole/v1/account-reset-display'||workspace!==resetWorkspace||!(login==='test-user'||login==='member'||login.startsWith('queue-'))||!request)throw Error('wrong reset binding');
  return {publicKey:displayMode==='bad-key'?'':'public-fixture',
    open:async()=>new Uint8Array(displayMode==='short'?47:48).fill(42),
    dispose:()=>{resetKeyDisposed++;}};
}
if(!crypto.randomUUID)Object.defineProperty(crypto,'randomUUID',{value:()=>resetWorkspace});
${resetQueueSource}
${resetIssueSource}
${administrationSource}
const mountCreateSlot=(()=>{
  const vaultID=${vaultID.toString()}, vaultRecord=${vaultRecord.toString()}, vaultFields=${vaultFields.toString()};
  ${slotSources.join('\n')}
  return mountCreateSlot;
})();
${suspensionInventorySource}
${groupSource}
const workspacePermissionLabels=['View','Use','Write','Reveal','Manage'];
function parseNodeGrantRequest(request){return request.subjectId||request.login?request:undefined}
${grantSource}
let finishAdminPage;
(async()=>{
  const check=(condition,message)=>{if(!condition)throw Error(message)};
  const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
  const card=document.createElement('main');
  document.body.append(card);
  const status=()=>card.querySelector('[role=status]').textContent;
  const field=name=>card.querySelector('[name="'+name+'"]');
  const fill=entries=>{for(const [name,value] of Object.entries(entries))field(name).value=value};
  const find=label=>Array.from(card.querySelectorAll('button')).find(button=>button.textContent===label);
  const click=async label=>{const target=find(label);check(target,'missing control '+label);target.click();await tick()};
  const enter=async()=>{card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));await tick()};
  const deployment={version:44,provisioning:true,requiresTls:true};
  {
    const card = document.createElement('section');
    document.body.append(card);
    let enabled = true, option = 'review', calls = [];
    let rotation = 'review', retired = false, personal = false, rotationCalls = [];
    let personalRecovery = 'review', recoveryCalls = [], submittedFactors, settleRecovery, enrollmentInput;
    let groupQueued=false, groupResolved=false, groupStale=false, groupMemberEnabled=false, staleRemoval=false, suspensionRevision='17', groupCalls=[], groupRotationCalls=[];
    const click = async label => {
      const button = [...card.querySelectorAll('button')].find(b=>b.textContent===label&&!b.closest('[hidden]'));
      check(button&&!button.disabled,'access action is unavailable: '+label);
      button.click();
      await tick();
    };
    mountSharedAdministration(card,{
      adminInventory:async ({kind})=>({status:'ready',page:{kind,entries:[kind==='accounts'
        ? {id:'acct',login:'member',name:'Test account',role:'member',status:enabled?'enabled':'disabled'}
        : {id:'device',login:'member',name:'Test device',status:'active',at:'2026-11-23T12:00:00.000000Z'}]}}),
      workspaceAccess:async request=>{
        calls.push(request);
        if(option==='exception')throw Error('private diagnostic');
        if(request.revision){
          if(option!=='review')return {status:option};
          enabled = request.action==='enable-account';
          return {status:'changed'};
        }
        if(option!=='review')return {status:option};
        return {status:'review',review:{...request,revision:'17',login:'member',name:'Test target',currentDevice:request.action==='revoke-device'}};
      },
      accountSuspension:async request=>{
        if(option==='exception')throw Error('sensitive diagnostic');
        if(option!=='review')return {status:option};
        const base={accountId:request.accountId,kind:request.kind,revision:suspensionRevision};
        if(request.kind==='passwords')return {status:'ready',page:{...base,entries:[{position:'1',boundaryId:'b',id:'p',kind:'credential',name:'Password reference'}]}};
        if(request.kind==='web-sessions')return {status:'ready',page:{...base,entries:[{position:'1',boundaryId:'b',id:'w',kind:'web-target',name:'Company portal'},{position:'2'}]}};
        if(request.kind==='groups')return {status:'ready',page:{...base,entries:[
          {position:'1',kind:'group',id:'selected-group',name:'Operations',revision:groupQueued?'41':'40',
            status:groupResolved?'resolved':groupQueued?'queued':'needs-removal',...(groupQueued&&!groupResolved?{jobId:'queued-job'}:{})},
          {position:'2',kind:'group',id:'waiting-group',name:'Support',revision:'8',status:'waiting'},
          {position:'3'},
        ]}};
        if(request.after)return {status:'ready',page:{...base,entries:[]}};
        return {status:'ready',page:{...base,entries:[
          {position:'1',boundaryId:'b',id:'key',kind:'secret',revision:'3',direct:true,groupCount:personal?'0':'2',status:retired?'retired':'active',...(personal?{personal:true}:{})},
          {position:'2'},
        ],after:'2'}};
      },
      accountBoundaryRotation:async request=>{
        rotationCalls.push(request);
        if(rotation==='exception')throw Error('sensitive rotation diagnostic');
        if(rotation!=='review')return {status:rotation};
        if(!request.review)return {status:'review',review:'digest'};
        retired=true;
        return {status:'changed'};
      },
      personalRootRecovery:async (request, factors)=>{
        recoveryCalls.push(request);
        if(personalRecovery==='exception')throw Error('private recovery diagnostic');
        if(personalRecovery==='eligible')return {status:'enrollment-required',canReenroll:true};
        if(personalRecovery!=='review')return {status:personalRecovery};
        if(!request.review){check(!factors,'review collected account factors');return {status:'review',review:'root-review',enrollment:'replacement-enrollment'};}
        check(request.review==='root-review'&&request.suspension==='17','recovery was submitted for different suspension');
        check(new TextDecoder().decode(factors.password)==='custodian-password'&&factors.ask.length===32&&factors.ask[0]===171,'fresh factors were not forwarded');
        submittedFactors=factors;
        await new Promise(resolve=>{settleRecovery=resolve;});
        return {status:'changed'};
      },
      resetContext:async()=>resetWorkspace,
      issueReset:async value=>{
        enrollmentInput=value;
        check(value.targetUserId==='acct'&&value.suspension==='17'&&value.targetLogin==='member','re-enrollment changed the reviewed recipient');
        check(new TextDecoder().decode(value.password)==='fixture-password','re-enrollment lost fresh credentials');
        return {status:'issued',handover:{workspaceId:resetWorkspace,requestId:value.requestId,bundle:{}}};
      },
      adminGroups:async request=>{
        groupCalls.push(request);
        if(groupStale)return {status:'stale'};
        if(request.action==='members'){
          const entry=request.after?{id:'acct',login:'member',status:groupMemberEnabled?'enabled':'disabled'}:{id:'other',login:'Unrelated member',status:'disabled'};
          return {status:'ready',page:{entries:groupQueued?[]:[entry],...(!groupQueued&&!request.after?{after:'other'}:{})}};
        }
        return {status:'key-change-required'};
      },
      memberRotation:async request=>{
        groupRotationCalls.push(request);
        if(request.action==='resume'){
          groupResolved=true;
          return {status:'complete'};
        }
        if(request.review){
          if(staleRemoval)return {status:'stale'};
          groupQueued=true;
          return {status:'rotated',receipt:{jobId:'queued-job',pending:2}};
        }
        return {status:'review',preview:{remaining:[],boundaries:2,review:'reviewed-group'}};
      },
      close:()=>{},
    });
    await tick();
    for(const [status, message] of [
      ['busy','workspace is busy'],['stale','already changed'],['unsupported','Update the workspace schema'],
      ['unavailable','unavailable'],['exception','Could not review'],
    ]){
      option=status;
      await click('Disable account');
      check(card.textContent.includes(message)&&!card.textContent.includes('private diagnostic'),'wrong access outcome: '+status);
    }
    option='review';
    await click('Disable account');
    check(card.textContent.includes('Test target')&&card.textContent.includes('will lose access'),'confirmation omitted the exact target');
    await click('Cancel');
    check(!calls.some(request=>request.revision),'cancel submitted a revision');
    await click('Disable account');
    option='stale';
    await click('Disable account');
    check(enabled&&card.textContent.includes('already changed'),'stale confirmation changed account');
    option='review';
    await click('Disable account');
    await click('Disable account');
    check(!enabled&&calls.at(-1).revision==='17'&&card.textContent.includes('Account disabled.'),'suspension did not refresh the account');
    await click('Review access at suspension');
    check(card.textContent.includes('Group copies (2)')&&card.textContent.includes('1 restricted entry'),'boundary inventory omitted an access route');
    check([...card.querySelectorAll('button')].find(b=>b.textContent==='Restore personal keys…').hidden,'active shared keys exposed personal recovery');
    for(const [state,message] of [
      ['group-rotation-required','related group rotations'],['unchanged','already been retired'],['busy','workspace is busy'],
      ['stale','suspension changed'],['unsupported','Update the workspace schema'],['unavailable','unavailable for rotation'],
      ['exception','Could not review the boundary key'],
    ]){
      rotation=state;
      await click('Rotate key…');
      check(card.textContent.includes(message)&&!card.textContent.includes('sensitive rotation diagnostic'),'wrong rotation feedback: '+state);
    }
    rotation='review';
    await click('Rotate key…');
    check(card.textContent.includes('Version 3'),'precise key version missing');
    await click('Cancel');
    check(!rotationCalls.some(request=>request.review),'cancel submitted the review digest');
    await click('Rotate key…');
    rotation='exception';
    await click('Confirm key rotation');
    check(card.textContent.includes('Could not confirm the rotation')&&!retired,'uncertain rotation looked successful');
    rotation='review';
    personal=true;
    await click('Refresh inventory');
    check(card.textContent.includes('Personal boundary b'),'personal root was not identified');
    await click('Rotate key…');
    check(card.textContent.includes('organisation will hold the replacement key'),'personal rotation omitted the recovery consequence');
    await click('Confirm key rotation');
    check(retired&&card.textContent.includes('Boundary key rotated.')&&card.textContent.includes('retired'),'confirmation did not refresh committed status');
    check(rotationCalls.at(-1).suspension==='17'&&rotationCalls.at(-1).rootVersion==='3'&&rotationCalls.at(-1).review==='digest','confirmation did not bind selected generation');
    for(const [state,message] of [
      ['rotation-required','Rotate both personal keys'],['enrollment-required','certified replacement enrollment'],
      ['stale','enrollment or suspension changed'],['busy','workspace is busy'],['unavailable','unavailable for this account'],
      ['unsupported','Update the workspace schema'],['unchanged','Personal keys restored.'],['exception','Could not review personal key recovery'],
    ]){
      personalRecovery=state;
      await click('Restore personal keys…');
      check(card.textContent.includes(message)&&!card.textContent.includes('private recovery diagnostic'),'wrong personal recovery feedback: '+state);
      check([...card.querySelectorAll('button')].find(b=>b.textContent==='Issue re-enrollment offer…').hidden,'unavailable review exposed offer issuance');
    }
    personalRecovery='eligible';
    await click('Restore personal keys…');
    await click('Issue re-enrollment offer…');
    const protectedLogin=card.querySelector('[name=target-login]');
    check(protectedLogin.readOnly&&protectedLogin.value==='member','re-enrollment accepted an editable login');
    protectedLogin.value='different-user';
    card.querySelector('[name=password]').value='fixture-password';
    card.querySelector('form').requestSubmit();
    await tick();
    check(enrollmentInput?.password.every(byte=>byte===0)&&card.textContent.includes('Deliver to member'),'handover was not shown for the reviewed account');
    const offerFactors=[...card.querySelectorAll('code')];
    check(offerFactors.length===2&&offerFactors.every(code=>code.textContent),'offer factors were missing');
    await click('Back to suspension');
    check(offerFactors.every(code=>!code.textContent)&&card.textContent.includes('Access at suspension'),'leaving the offer retained factors or lost the suspension');
    personalRecovery='review';
    await click('Restore personal keys…');
    check(card.textContent.includes('View and Secret keys')&&card.textContent.includes('replacement-enrollment'),'review omitted selected enrollment');
    const formField=name=>card.querySelector('input[name="'+name+'"]');
    formField('password').value='cancelled password';
    const cancelledPassword=formField('password');
    await click('Cancel');
    check(!cancelledPassword.value&&!recoveryCalls.some(request=>request.review),'cancel retained factors or submitted a mutation');
    await click('Restore personal keys…');
    formField('password').value='invalid input';
    formField('ask').value='wrong';
    await click('Restore both keys');
    check(card.textContent.includes('check the Account Secret Key format')&&formField('password').value===''&&!recoveryCalls.some(request=>request.review),'invalid ASK passed the protected form');
    formField('password').value='custodian-password';
    formField('ask').value='ab'.repeat(32);
    personalRecovery='invalid-authentication';
    await click('Restore both keys');
    check(card.textContent.includes('reopen the review'),'invalid factors looked like success');
    personalRecovery='review';
    await click('Restore personal keys…');
    formField('password').value='custodian-password';
    formField('ask').value='ab'.repeat(32);
    await click('Restore both keys');
    check(card.textContent.includes('Restoring personal keys')&&submittedFactors.password.every(x=>x===0)&&submittedFactors.ask.every(x=>x===0),'pending recovery retained the factors');
    settleRecovery();
    await tick();
    check(card.textContent.includes('Personal keys restored.'),'successful recovery did not update the panel');
    check(recoveryCalls.at(-1).accountId==='acct'&&calls.at(-1).action==='disable-account','restoring keys silently re-enabled the account');
    await click('Next page');
    check(card.textContent.includes('No entries were recorded.'),'next inventory page did not load');
    await click('Previous page');
    check(card.textContent.includes('Personal boundary b'),'previous inventory page did not restore');
    const kind=card.querySelectorAll('select')[1];
    kind.value='web-sessions';
    kind.dispatchEvent(new Event('change'));
    await tick();
    check(card.textContent.includes('Company portal · w')&&card.textContent.includes('1 restricted entry')&&!card.textContent.includes('Group copies'),'web inventory did not display the scoped target and restricted position');
    kind.value='passwords';
    kind.dispatchEvent(new Event('change'));
    await tick();
    check(card.textContent.includes('Password reference')&&!card.textContent.includes('Group copies'),'password tab retained roots or missed a reference');
    for(const [state,message] of [
      ['busy','workspace is busy'],['stale','suspension record changed'],['unsupported','Update the workspace schema'],
      ['not-recorded','no recorded access inventory'],['unavailable','inventory is unavailable'],['exception','Could not load'],
    ]){
      option=state;
      await click('Refresh inventory');
      check(card.textContent.includes(message)&&!card.textContent.includes('sensitive diagnostic'),'incorrect inventory feedback: '+state);
    }
    option='review';
    kind.value='groups';
    kind.dispatchEvent(new Event('change'));
    await tick();
    check(card.textContent.includes('Operations')&&card.textContent.includes('Member removal needed')&&card.textContent.includes('Another rotation is in progress')&&card.textContent.includes('1 restricted entry'),'group review omitted its current statuses');
    groupStale=true;
    await click('Open group review');
    check(card.textContent.includes('group changed')&&!groupRotationCalls.length,'outdated group coordinates reached rotation');
    await click('Back to groups at suspension');
    groupStale=false;
    await click('Open group review');
    check(groupCalls.at(-1).action==='members'&&groupCalls.at(-1).groupId==='selected-group'&&groupCalls.at(-1).revision==='40','suspension did not open the exact group');
    check(!card.textContent.includes('Unrelated member')&&!card.textContent.includes('Rename group')&&card.textContent.includes('absent from this member page'),'suspension review offered unrelated members or edits');
    groupMemberEnabled=true;
    await click('More members');
    check(card.textContent.includes('This account is enabled')&&![...card.querySelectorAll('button')].some(b=>b.textContent==='Review member removal'),'a freshly enabled member could be removed from the suspended-account review');
    await click('First members page');
    groupMemberEnabled=false;
    await click('More members');
    await click('Review member removal');
    staleRemoval=true;
    await click('Confirm member removal and queue keys');
    check(!groupQueued&&groupRotationCalls.at(-1).suspension==='17'&&card.textContent.includes('suspension or group changed'),'stale suspension looked like a committed removal');
    suspensionRevision='18';
    staleRemoval=false;
    await click('Back to groups at suspension');
    await click('Open group review');
    await click('More members');
    await click('Review member removal');
    await click('Confirm member removal and queue keys');
    check(groupQueued&&groupRotationCalls.at(-1).memberId==='acct'&&groupRotationCalls.at(-1).review==='reviewed-group'&&groupRotationCalls.at(-1).suspension==='18','confirmation did not bind the suspended member and current suspension');
    check(groupCalls.every(request=>request.action==='members'),'suspended group actions used the ordinary membership mutation');
    check(!groupRotationCalls.some(request=>request.action==='resume'),'suspended member removal resumed before the other groups could queue');
    await click('Back to groups at suspension');
    await click('Open queued rotation');
    check(groupCalls.at(-1).revision==='41','queued group did not refresh its revision');
    await click('Resume key rotation');
    check(groupRotationCalls.at(-1).jobId==='queued-job'&&card.textContent.includes('Member removed'),'resume did not use the captured job and refresh the review');
    await click('Back to accounts');
    option='personal-recovery-required';
    await click('Enable account');
    check(!enabled&&card.textContent.includes('Restore personal access before re-enabling this account.'),'enable ignored missing personal custody');
    option='review';
    await click('Enable account');
    check(card.textContent.includes('can sign in again'),'enable confirmation lacked the consequence');
    await click('Enable account');
    check(enabled&&card.textContent.includes('Account enabled.'),'enablement did not refresh the account');
    const section=card.querySelector('select');
    section.value='my-devices';
    section.dispatchEvent(new Event('change'));
    await tick();
    await click('Revoke device');
    check(card.textContent.includes('This device will be signed out'),'current device warning missing');
    await click('Revoke device');
    check(calls.at(-1).action==='revoke-device'&&card.textContent.includes('Device revoked.'),'revocation confirmation missing');
    card.remove();
    const own=document.createElement('section');
    document.body.append(own);
    mountSharedAdministration(own,{
      adminInventory: async request=>{
        check(request.kind==='my-devices','member requested the administrator inventory');
        return {status:'ready',page:{kind:request.kind,entries:[]}};
      },
      adminGroups:async ()=>({status:'unavailable'}),
      close:()=>{},
    },true);
    await tick();
    check(own.querySelector('h1').textContent==='My devices'&&own.querySelector('select').options.length===1,'members could see administration sections');
    own.remove();
  }
  {
    const adminCard = document.createElement('section');
    document.body.append(adminCard);
    let state = 'ready', release, closed = 0, createStatus='busy', submitted=[];
    const bySection = {
      accounts:{id:'account',name:'Workspace Administrator',login:'alice',role:'administrator',status:'enabled'},
      devices:{id:'device',login:'alice',status:'revoked',at:'2026-11-23T12:00:00.000000Z'},
      'unencrypted-clients':{id:'client',name:'Lab desktop',login:'alice',status:'active',at:'2026-11-23T12:00:00.000000Z'},
      sessions:{id:'session',login:'alice',appVersion:'2.4.3',transport:'tls',deviceId:'device',at:'2026-11-23T12:00:00.000000Z'},
      slots:{id:'slot',name:'Production shell',protocol:'ssh',allowSelfService:true},
      audit:{id:'event',login:'',actorId:'deleted-account',sessionId:'session',action:'login',status:'success',source:'ui',at:'2026-11-23T12:00:00.000000Z'},
    };
    mountSharedAdministration(adminCard,{
      adminGroups: async ()=>({status:'unsupported'}),
      createSlot: async request=>{
        submitted.push(request);
        if(createStatus==='failure')throw Error('private diagnostic');
        if(createStatus==='delayed')return new Promise(resolve=>{release=()=>resolve({status:'saved'})});
        return {status:createStatus};
      },
      grantTargets: async ()=>({nodes:[],next:null}),
      nodeGrant: async ()=>({status:'unsupported'}),
      adminInventory: async ({kind,next})=>{
        if(state==='failure')throw Error('private inventory error');
        if(state==='delay')await new Promise(resolve=>{release=resolve});
        if(state==='unsupported'||state==='unavailable')return{status:state};
        return{status:'ready',page:{kind,entries:next||state==='empty'?[]:[bySection[kind]],...(!next&&kind==='accounts'?{next:{id:'account'}}:{})}};
      },
      close:()=>{closed++},
    });
    const adminStatus=()=>adminCard.querySelector('[role=status]').textContent;
    const list=()=>adminCard.querySelector('.shared-administration-list').textContent;
    const press=async name=>{[...adminCard.querySelectorAll('button')].find(item=>item.textContent===name).click();await tick()};
    await tick();
    check(list().includes('Workspace Administrator'),'account name missing');
    await press('Next page');
    check(adminStatus().includes('No records')&&!list(),'empty result retained account data');
    await press('Previous page');
    check(list().includes('alice'),'previous cursor did not restore the account page');
    const menu=adminCard.querySelector('select');
    menu.value='groups';
    menu.dispatchEvent(new Event('change'));
    await tick();
    check(adminCard.textContent.includes('Update the workspace schema to manage groups')&&!list(),'groups section retained inventory or hid schema feedback');
    menu.value='grants';
    menu.dispatchEvent(new Event('change'));
    await tick();
    check(adminCard.textContent.includes('No manageable items')&&!list(),'grants section retained the previous section');
    for(const [value,expected] of [['devices','revoked'],['sessions','2.4.3'],['audit','deleted-account'],['slots','Production shell']]){
      menu.value=value;
      menu.dispatchEvent(new Event('change'));
      await tick();
      check(list().includes(expected),'section did not display its expected record');
    }
    check(list().includes('SSH · Users can choose a credential')&&!adminCard.querySelector('li button'),'slot metadata or permissions changed in the view');
    const fillSlot=()=>{
      const details=adminCard.querySelector('details');
      details.open=true;
      const form=details.querySelector('form');
      form.querySelector('input').value='  ';
      form.requestSubmit();
      check(form.textContent.includes('Enter a slot name')&&!submitted.length,'blank name reached the native port');
      form.querySelector('input').value='My RDP';
      form.querySelector('select').value='rdp';
      form.querySelector('[type=checkbox]').checked=true;
      return form;
    };
    const slotForm=fillSlot();
    for(const [result,message] of [['busy','busy'],['failure','Retry to check'],['unavailable','permission'],['unsupported','Update'],['stale','workspace changed']]){
      createStatus=result;
      slotForm.requestSubmit();
      await tick();
      check(slotForm.textContent.includes(message)&&submitted.at(-1).id===submitted[0].id,'creation retry lost identity or feedback');
    }
    createStatus='delayed';
    slotForm.requestSubmit();
    slotForm.requestSubmit();
    check(menu.disabled&&submitted.length===6,'concurrent slot submission reached the port');
    release();
    await tick();
    check(!menu.disabled&&adminCard.textContent.includes('Created credential slot')&&submitted.at(-1).protocol==='rdp'&&submitted.at(-1).allowSelfService,'saved slot was not confirmed');
    bySection.slots.allowSelfService=false;
    await press('Refresh');
    check(list().includes('SSH · Assigned by an administrator'),'assignment policy remained stale');
    menu.value='unencrypted-clients';
    menu.dispatchEvent(new Event('change'));
    await tick();
    check(list().includes('Lab desktop')&&list().includes('Connected since')&&!adminCard.querySelector('li button'),'live client row omitted its connection time or exposed a mutation');
    state='empty';
    await press('Refresh');
    check(!list()&&adminStatus()==='No unencrypted clients connected.','disconnected client remained visible');
    for(const [value,expected] of [['unsupported','Update the workspace schema'],['unavailable','unavailable for this account'],['failure','Could not load']]){
      state=value;
      await press('Refresh');
      check(!list()&&adminStatus().includes(expected),'failed request retained stale records or missed status');
    }
    await press('Close');
    check(closed===1,'close did not reach the owner');
    state='delay';
    await press('Refresh');
    // Run the pagehide cleanup at the end of the other wizard cases below.
    finishAdminPage=async()=>{
      window.dispatchEvent(new Event('pagehide'));
      release();
      await tick();
      check(!list(),'a late reply rendered after pagehide');
    };
  }
  const prerequisites={serverVersion:150000,maxConnections:100,tls:'verified',canCreateRoles:false,ownsDatabase:false,ownsPublicSchema:false,canGrantStatistics:false,emptyDatabase:false,logsStatements:true,logsParameters:true,statementTracking:'all'};
  const s={hosting:'managed',host:'host.example',port:5432,database:'vault',workspaceId:'workspace',roleTag:'role',state:'prepared'};
  let plan=null, administrator, serverKit, preflight=0, exports=0, publications=0, csrAttempts=0, last, closes=0;
  let catalogMatches=true;
  let preflightFailure;
  const actions=[];
  const response=()=>({plan,adminPending:true,administrator});
  const setStage=stage=>{administrator={enrollmentId:'admin-id',loginName:'first-admin',stage};return response()};
  mountSharedSetup(card,{contentProtectionAvailable:false,close:async()=>{closes++;throw Error('internal close detail')},request:async request=>{
    last=request;
    actions.push(request.action);
    switch(request.action){
      case 'plan': return {plan,joinAvailable:true,...(administrator?{adminPending:true}:{})};
      case 'prepare': plan=s; return {plan};
      case 'prepare-tls':
        if(++csrAttempts===1) return {plan:null,failure:'csr'};
        plan={...s,hosting:'self-hosted'};
        return {plan,tls:{caPem:'public CA fixture',serverPem:'public leaf fixture'}};
      case 'prepare-generated-tls':
        plan={...s,hosting:'self-hosted'};
        serverKit={folder:'/cache/server-package',state:'pending'};
        return {plan,serverKit};
      case 'save-server-kit':
        serverKit={...serverKit,state:'saved'};
        return {plan,serverKit};
      case 'discard': plan=null; serverKit=undefined; return {plan};
      case 'export-hba': return {plan,failure:'export-failed'};
      case 'preflight': return preflightFailure ? {plan,failure:preflightFailure} : {plan,preflight:++preflight===1?prerequisites:{...prerequisites,serverVersion:160000,canCreateRoles:true,ownsDatabase:true,ownsPublicSchema:true,canGrantStatistics:true,emptyDatabase:true}};
      case 'run': plan={...s,state:'submitted'};throw Error('lost commit reply');
      case 'check': return catalogMatches ? {plan,deployment,checks:{plainStartup:'unconfirmed',maxConnections:120,logsStatements:true,logsParameters:true,statementTracking:'all'}} : {plan,failure:'mismatch'};
      case 'admin-prepare': return setStage('prepared');
      case 'admin-open': return response();
      case 'admin-recovery': return ++exports===1?null:{...setStage('recovery-exported'),recovery:{groups:[1,11]}};
      case 'admin-confirm': return setStage('recovery-confirmed');
      case 'admin-publish':
        if(++publications===1) return {...response(),failure:'scram'};
        setStage('published');
        throw Error('lost publication reply');
      case 'admin-join': return null;
      default: throw Error('unexpected test action');
    }
  }});
  await tick();
  check(!field('csr').closest('fieldset').hidden && field('caPem').disabled,'workspace CA was not offered first');
  fill({tlsSource:'generate',host:s.host,port:'5432',database:s.database});
  field('tlsSource').dispatchEvent(new Event('change'));
  check(field('csr').disabled && !field('keyPassphrase').closest('fieldset').disabled,'generation did not select a separate passphrase');
  const serverPassphrase='synthetic-independent-key-factor';
  const serverFactors=(confirmation)=>fill({accountPassword:'synthetic-account',confirm:'synthetic-account',keyPassphrase:serverPassphrase,confirmPassphrase:confirmation});
  serverFactors('different');
  await click('Generate server key');
  check(!actions.includes('prepare-generated-tls') && status().includes('separate server key passphrase') &&
    field('keyPassphrase').value==='','mismatched passphrase crossed the bridge');
  serverFactors(serverPassphrase);
  await click('Generate server key');
  check(find('Save server files') && !field('keyPassphrase') &&
    last.keyPassphrase.every(value=>value===0),'generated key flow retained its passphrase');
  fill({hbaNetworks:'localhost'});
  await click('Export pg_hba.conf rules');
  check(!actions.includes('export-hba') && status().includes('CIDR'),'invalid address reached the picker');
  fill({hbaNetworks:'::1'});
  await click('Export pg_hba.conf rules');
  check(status().includes('new .conf file') && field('hbaNetworks').value==='::1','failed export lost the input or omitted its recovery hint');
  await click('Save server files');
  check(field('serverKitFolder').readOnly && field('serverKitFolder').value==='/cache/server-package' &&
    !find('Delete local server key'),'saved server files enabled premature deletion');
  await click('Change database');
  fill({host:s.host,port:'5432',database:s.database,aliases:'127.0.0.1,bad$host'});
  await click('Show server commands');
  check(status().includes('valid DNS'),'shell punctuation was accepted');
  fill({aliases:'127.0.0.1,::1'});
  await click('Show server commands');
  check(card.querySelector('pre').textContent.includes('DNS:host.example,IP:127.0.0.1,IP:::1'),'server commands did not include the requested names');
  const csr='-----BEGIN CERTIFICATE REQUEST-----\\nQUJD\\n-----END CERTIFICATE REQUEST-----';
  const csrCredentials=()=>fill({accountPassword:'synthetic-account',confirm:'synthetic-account',ask:'4b'.repeat(32)});
  csrCredentials(); fill({csr:'-----BEGIN PRIVATE KEY-----'}); await click('Sign certificate request');
  check(!actions.includes('prepare-tls') && field('csr').value==='' && field('accountPassword').value==='','private material crossed the bridge');
  csrCredentials(); fill({csr,confirm:'different'}); await click('Sign certificate request');
  check(!actions.includes('prepare-tls') && status().includes('Check the administrator'),'mismatched factors crossed the bridge');
  csrCredentials(); await click('Sign certificate request');
  check(status().includes('could not be signed') && field('csr').value===csr,'rejected CSR could not be corrected');
  csrCredentials(); await click('Sign certificate request');
  check(last.action==='prepare-tls' && last.accountPassword.every(value=>value===0) &&
    last.ask.every(value=>value===0) && field('serverCertificate').readOnly &&
    field('workspaceCA').value==='public CA fixture','public issuance retained secrets or omitted certificates');
  await click('Change database');
  fill({tlsSource:'external'});
  field('tlsSource').dispatchEvent(new Event('change'));
  check(field('csr').closest('fieldset').hidden && !field('caPem').disabled,'existing CA input was unreachable');
  fill({hosting:'managed',host:s.host,port:'5432',database:s.database,caPem:'synthetic public certificate'});
  field('hosting').dispatchEvent(new Event('change'));
  check(field('caPem').closest('label').textContent.includes('Provider'),'managed CA label missing');
  await click('Continue');
  const dba=()=>fill({role:'dba',password:'synthetic-dba'});
  check(find('Deploy schema').disabled,'enabled before preflight');
  dba(); await enter();
  check(find('Deploy schema').disabled && card.querySelectorAll('li').length>=6,'invalid preflight allowed deploy');
  check(card.textContent.includes('max_connections is 100'),'preflight omitted the server capacity');
  dba(); await click('Test connection');
  check(!find('Deploy schema').disabled && last.password.every(value=>value===0),'preflight retained credentials');
  field('role').dispatchEvent(new Event('input'));
  check(find('Deploy schema').disabled,'changed DBA role retained prior preflight');
  preflightFailure='channel-binding'; dba(); await click('Test connection');
  check(find('Deploy schema').disabled && status().includes('did not offer SCRAM-SHA-256-PLUS'),'missing channel binding enabled deployment');
  preflightFailure='connection-limit'; dba(); await click('Test connection');
  check(find('Deploy schema').disabled && status().includes('server is at its connection limit'),'connection exhaustion lost its diagnostic');
  preflightFailure=undefined;
  dba(); await click('Test connection'); dba(); await click('Deploy schema');
  check(status().includes('interrupted'),'lost dispatch could be replayed');
  await click('Reload deployment plan'); dba(); await enter();
  check(find('Create first administrator'),'verified deployment did not allow administrator setup');
  for(const message of ['plaintext startup check was inconclusive','provider’s TLS enforcement','max_connections is 120','log_statement','log_parameter_max_length','pg_stat_statements.track']){
    check(card.textContent.includes(message),'deployment check omitted '+message);
  }
  catalogMatches=false; dba(); await click('Check deployment');
  check(!find('Create first administrator') && status().includes('access grants'),'failed check reused a previous deployment verification');
  catalogMatches=true; dba(); await click('Check deployment');
  await click('Create first administrator');
  const account=()=>fill({accountPassword:'synthetic-account',ask:'4b'.repeat(32)});
  const prepare=(confirmation)=>{ dba(); account(); fill({loginName:'FIRST-ADMIN',confirm:confirmation,profile:'standard'}) };
  prepare('different'); await click('Prepare administrator');
  check(!actions.includes('admin-prepare') && field('accountPassword').value==='','mismatched password crossed the bridge');
  prepare('synthetic-account');
  field('ask').value='invalid'; await click('Prepare administrator');
  check(!actions.includes('admin-prepare'),'invalid ASK crossed the bridge');
  prepare('synthetic-account');
  for(const [devices,budget] of [['300','620'],['301','622'],['1','22'],['1.5',''],['','']]){
    fill({directConnectionDevices:devices}); field('directConnectionDevices').dispatchEvent(new Event('input'));
    const value=card.querySelector('#shared-connection-budget').textContent;
    check(budget?value.includes('at least '+budget+'.'):value==='','incorrect connection budget for '+devices);
  }
  fill({directConnectionDevices:'300'}); await enter();
  check(last.directConnectionDevices===300,'direct deployment size was not sent for signature');
  check(last.loginName==='first-admin' && last.ask.every(value=>value===0),'admin profile fields were not consumed');
  failKeyGeneration=true; account(); await click('Save recovery kit and show key');
  check(status().includes('could not be opened') && !status().includes('diagnostic'),'private recovery error escaped');
  failKeyGeneration=false; account(); await click('Save recovery kit and show key');
  check(!card.querySelector('code[data-recovery]'),'cancelled picker exposed recovery code');
  account(); await click('Save recovery kit and show key');
  const recovery=card.querySelector('code[data-recovery]');
  check(recovery?.textContent.startsWith('WHREC1-') && !field('groupFirst'),'code shown with challenge inputs');
  const displaySubmit=new Event('submit',{cancelable:true});
  check(!card.querySelector('form').dispatchEvent(displaySubmit),'recovery display allowed form navigation');
  check(card.textContent.includes('Screen capture protection is unavailable'),'capture warning missing');
  for(const kind of ['copy','cut','dragstart'])check(!recovery.dispatchEvent(new Event(kind,{bubbles:true,cancelable:true})),'secret clipboard event accepted');
  await click('I saved the recovery key');
  check(recovery.textContent==='' && !card.textContent.includes('WHREC1-'),'code remained displayed');
  account(); fill({groupFirst:'ABCDE',groupSecond:'Z'}); await enter();
  check(!actions.includes('admin-confirm'),'short groups crossed the bridge');
  account(); fill({groupFirst:'ABCDE',groupSecond:'ABCDE'}); await enter();
  check(last.groups.every(value=>value===0),'confirmation groups survived dispatch');
  account(); dba(); await click('Create administrator invitation');
  check(status().includes('SCRAM authentication failed'),'publication lost its retry stage');
  account(); dba(); await click('Create administrator invitation');
  check(status().includes('interrupted'),'lost publication did not require reloading the checkpoint');
  await click('Reload deployment plan');
  account(); await click('Unlock setup');
  account(); await click('Join workspace');
  check(last.action==='admin-join' && last.accountPassword.every(value=>value===0),'join retained its password');
  await click('Close'); check(closes===1 && status().includes('busy'),'close failure did not surface');
  account(); window.dispatchEvent(new Event('pagehide'));
  check(field('accountPassword').value==='' && field('ask').value==='','pagehide retained credentials');
})().then(async()=>{
  const card=document.createElement('section');
  document.body.append(card);
  let sent, submits=0, outcome='cancel';
  mountAdminRecovery(card,input=>{
    sent=input;submits++;
    if(outcome==='throw')throw Error('private');
    return Promise.resolve(outcome==='complete');
  },()=>Promise.reject(Error('private')));
  const field=name=>card.querySelector('[name='+name+']');
  const submit=()=>card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));
  const status=()=>card.querySelector('[role=status]').textContent;
  const check=(condition,message)=>{if(!condition)throw Error(message)};
  const factors=(confirm='pw',key='ab'.repeat(32))=>{
    field('recoveryCode').value='recovery code';
    field('deployerPassword').value='DBA password';
    field('accountPassword').value='pw';
    field('confirmPassword').value=confirm;
    field('ask').value=key;
  };
  const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
  factors();
  submit();
  check(submits===0,'recovery was sent without consent');
  field('confirmed').checked=true;
  factors('mismatch');submit();
  check(submits===0&&status().includes('confirmation')&&!field('accountPassword').value,'password mismatch kept factors');
  factors();
  submit();
  submit();
  await tick();
  check(submits===1&&status().includes('cancelled')&&sent.recoveryCode.every(value=>value===0)&&sent.ask.every(value=>value===0),'cancel lost input guard or wipe');
  outcome='throw';factors('pw','');submit();await tick();
  check(submits===2&&status().includes('Could not recover')&&!status().includes('private'),'recovery exposed a diagnostic');
  card.querySelector('button[type=button]').click();await tick();
  check(status().includes('Could not close'),'close refusal was hidden');
  outcome='complete';factors();submit();await tick();
  factors();window.dispatchEvent(new Event('pagehide'));submit();
  check(submits===3&&[...card.querySelectorAll('input[type=password]')].every(input=>!input.value),'pagehide retained factors');
}).then(async()=>{
  const card=document.createElement('section');document.body.append(card);
  const check=(condition,message)=>{if(!condition)throw Error(message)};
  const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
  let outcome=null,calls=0,borrowed,release;
  const controls={contentProtectionAvailable:false,backupContext:async()=>true,
    close:async()=>{throw Error('private');},exportBackup:input=>{
      calls++;borrowed=input;
      if(outcome==='pending')return new Promise(resolve=>release=resolve);
      if(outcome==='reject')throw Error('private');
      return Promise.resolve(outcome===null?null:{status:outcome,receipt:{}});
    }};
  await mountSharedBackup(card,controls);
  const send=()=>card.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));
  const status=()=>card.querySelector('[role=status]').textContent;
  const factors=(password='test password',ask='4b'.repeat(32))=>{
    card.querySelector('[name=password]').value=password;
    card.querySelector('[name=ask]').value=ask;
  };
  send();await tick();check(calls===0&&status().includes('Enter your password'),'empty factors crossed the bridge');
  factors('test password','not hex');send();await tick();
  check(calls===0&&status().includes('Account Secret Key format'),'invalid factor crossed the bridge');
  for(const value of [null,'unavailable','authentication-required','invalid-authentication','too-large','save-failed','reject']){
    const expected={null:'cancelled',unavailable:'unavailable','authentication-required':'reopen',
      'invalid-authentication':'Check your Wormhole','too-large':'maximum','save-failed':'Choose a new file',reject:'Could not export'};
    outcome=value;factors();send();send();await tick();
    check(status().includes(expected[value])&&!status().includes('private'),'unexpected backup result');
    check(Object.values(borrowed).every(bytes=>bytes.every(byte=>byte===0)),'backup IPC retained factors');
  }
  check(calls===7,'concurrent submit duplicated the export');
  outcome='exported';factors();send();await tick();
  const code=card.querySelector('code[data-recovery]');
  check(!code.hidden&&code.textContent.startsWith('WHREC1-'),'generated code did not appear');
  check(card.textContent.includes('Screen capture protection is unavailable'),'capture warning missing');
  for(const kind of ['copy','cut','dragstart'])check(!code.dispatchEvent(new Event(kind,{bubbles:true,cancelable:true})),'code left display');
  check(!document.body.dispatchEvent(new Event('copy',{bubbles:true,cancelable:true})),'copy from outside the card could export selected text');
  send();await tick();check(calls===8,'completed export sent a duplicate request');
  card.querySelector('button[type=button]').click();await tick();
  check(code.hidden&&!code.textContent&&status().includes('Could not close'),'close error retained the recovery password');
  card.remove();
  const defaultCard=document.createElement('section');document.body.append(defaultCard);
  await mountSharedBackup(defaultCard,{...controls,contentProtectionAvailable:true,backupContext:async()=>false});
  check(!defaultCard.querySelector('input'),'Default export requested factors');
  const submitDefault=()=>defaultCard.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));
  failKeyGeneration=true;submitDefault();await tick();
  check(defaultCard.textContent.includes('Could not export')&&calls===8,'failed key generation dispatched export');
  failKeyGeneration=false;failRecoveryDisplay=true;submitDefault();await tick();
  check(defaultCard.textContent.includes('password could not be displayed')&&calls===9,'failed opening of an exported receipt was unclear');
  defaultCard.remove();
  const pendingCard=document.createElement('section');document.body.append(pendingCard);
  await mountSharedBackup(pendingCard,{...controls,backupContext:async()=>false});
  outcome='pending';pendingCard.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));await tick();
  window.dispatchEvent(new Event('pagehide'));release({status:'exported',receipt:{}});await tick();
  check(pendingCard.querySelector('code').hidden&&!pendingCard.querySelector('code').textContent,'late receipt created a recovery display');
}).then(async()=>{
  const card=document.createElement('section');document.body.append(card);
  const check=(condition,message)=>{if(!condition)throw Error(message)};
  const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
  const summary={workspaceId:'11111111-1111-4111-8111-111111111111',roleTag:'archivetag',sourceSchemaVersion:49,profile:'standard',accounts:2,nodes:1};
  let reply=null,calls=0,borrowed,finish,restoreCalls=0,restoreIntent,restoreReply='restored';
  mountSharedRestore(card,request=>{
    calls++;borrowed=request;
    if(reply==='error')throw Error('private');
    if(reply==='pending')return new Promise(resolve=>finish=resolve);
    return Promise.resolve(reply);
  },async()=>{throw Error('private');},request=>{
    restoreCalls++;restoreIntent=request;
    if(restoreReply==='error')throw Error('private');
    return Promise.resolve(restoreReply);
  });
  const form=card.querySelector('form'),field=card.querySelector('input'),[open,save,apply,close]=card.querySelectorAll('button');
  const submit=button=>form.dispatchEvent(new SubmitEvent('submit',{cancelable:true,submitter:button}));
  const status=()=>card.querySelector('[role=status]').textContent;
  const factor=()=>{field.value='a'.repeat(76)};
  field.value='too short';submit(open);check(calls===0&&!field.value&&status().includes('full'),'malformed factor crossed the bridge');
  for(const [response,wanted] of [
    [null,'cancelled'],
    [{status:'invalid-password'},'was not accepted'],
    [{status:'invalid-backup'},'Could not authenticate'],
    [{status:'ready',summary},'Backup authenticated'],
    [{status:'saved',summary:{...summary,profile:'default'}},'Deployment SQL saved'],
    [{status:'save-failed',summary},'Could not save'],
    ['error','Could not inspect'],
  ]){
    reply=response;factor();submit(response?.status==='saved'?save:open);
    if(response!=='error')submit(save);
    await tick();
    check(!field.value&&borrowed.password.every(byte=>byte===0),'restore retained its password');
    check(borrowed.saveScript===(response?.status==='saved'),'save intent was lost or duplicated');
    check(status().includes(wanted)&&!status().includes('private'),'expected '+wanted+' but saw '+status());
    const rows=[...card.querySelectorAll('li')].map(li=>li.textContent).join(' ');
    check(rows.includes(summary.workspaceId)===!!response?.summary,'stale or missing summary');
  }
  check(calls===7,'double inspection escaped its guard');
  factor();submit(apply);await tick();check(restoreCalls===0,'apply opened a target without inspection');
  reply={status:'ready',summary};factor();submit(open);await tick();
  const fields=form.elements;
  fields.host.value='db.example.test';
  fields.database.value='recovered';
  fields.deployerPassword.value='synthetic-deployer';
  factor();submit(apply);await tick();check(restoreCalls===0,'apply did not require destination confirmation');
  for(const [outcome,message] of [['logging-enabled','parameter logging'],['uncertain','Retry with the same'],['error','Retry with the same'],['archive-changed','Inspect it again']]){
    restoreReply=outcome;fields.deployerPassword.value='synthetic-deployer';fields.confirmed.checked=true;
    factor();submit(apply);await tick();
    check(restoreIntent.confirmed&&restoreIntent.database==='recovered'&&restoreIntent.port===5432,'destination request drifted');
    check(restoreIntent.password.every(byte=>byte===0)&&restoreIntent.deployerPassword.every(byte=>byte===0),'apply retained copied factors');
    check(!fields.confirmed.checked&&!fields.deployerPassword.value&&status().includes(message),'restore retry state incorrect');
  }
  check(form.querySelector('fieldset').hidden&&!card.querySelector('li'),'changed archive retained its preview');
  factor();submit(open);await tick();
  restoreReply='restored';fields.deployerPassword.value='synthetic-deployer';fields.confirmed.checked=true;
  factor();submit(apply);await tick();
  check(form.querySelector('fieldset').hidden&&status().includes('Workspace restored.')&&restoreCalls===5,'completed restore did not retire its form');
  factor();close.click();await tick();check(!field.value&&status().includes('Could not close'),'close did not clear factors');
  reply='pending';factor();submit(open);await tick();
  window.dispatchEvent(new Event('pagehide'));finish({status:'ready',summary});await tick();
  check(!field.value&&!card.querySelector('li'),'late inspection updated a retired page');
  {
  const resetCard=document.createElement('section');document.body.append(resetCard);
  let invalidContext=false;
  try{await mountSharedAccountResetIssue(resetCard,{resetContext:async()=>null});}catch{invalidContext=true;}
  check(invalidContext,'unbound reset screen loaded');
  let answered,borrowed,resolveReset;
  const resetApi={contentProtectionAvailable:true,resetContext:async()=>resetWorkspace,close:async()=>{throw Error('internal close failure')},
    issueReset:value=>{borrowed=value;
      if(answered==='throw')throw Error('internal submit failure');
      if(answered==='promise')return new Promise(resolve=>resolveReset=resolve);
      if(answered==='success'||answered==='mismatch')return Promise.resolve({status:'issued',handover:{workspaceId:answered==='success'?resetWorkspace:'foreign',requestId:value.requestId,bundle:{}}});
      return Promise.resolve(answered);
    }};
  const sendReset=async({login='test-user',pass='fixture-pass',ask='4a'.repeat(32)}={})=>{
    for(const [name,value] of Object.entries({'target-login':login,password:pass,ask}))resetCard.querySelector('[name="'+name+'"]').value=value;
    resetCard.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));
    await tick();
  };
  const resetStatus=()=>resetCard.querySelector('[role=status]').textContent;
  await mountSharedAccountResetIssue(resetCard,resetApi);
  for(const values of [{login:''},{pass:''},{ask:'bad'}]){
    await sendReset(values);check(resetStatus().includes('Check the login')&&!borrowed,'invalid reset form reached the bridge');
  }
  for(const [answer,hint] of [[null,'File selection cancelled'],[{status:'invalid-authentication'},'Check your password'],[{status:'save-failed'},'Could not save'],[{},'Could not confirm'],['throw','Could not confirm']]){
    answered=answer;await sendReset();check(resetStatus().includes(hint),'unexpected reset refusal');
    check([borrowed.password,borrowed.ask,borrowed.recipient].every(bytes=>bytes.every(value=>value===0)),'reset factors were retained after IPC');
  }
  displayMode='bad-key';await sendReset();check(resetStatus().includes('Could not confirm'),'invalid recipient reached reset bridge');
  displayMode='';answered='success';
  await sendReset({ask:''});
  check(!borrowed.ask&&resetStatus().includes('Offer issued.'),'reset handover did not render');
  const displays=[...resetCard.querySelectorAll('code')];
  check(displays[0].textContent==='2a'.repeat(16)&&displays[1].textContent==='2a'.repeat(32),'reset code and ASK were not separate');
  check(!document.dispatchEvent(new Event('copy',{cancelable:true})),'reset display allowed copying');
  [...resetCard.querySelectorAll('button')].find(button=>button.textContent==='Close').click();await tick();
  check(displays.every(code=>code.textContent==='')&&resetStatus().includes('Could not close'),'close retained displayed reset factors');
  for(const mode of ['mismatch','short']){
    await mountSharedAccountResetIssue(resetCard,resetApi);
    answered=mode==='mismatch'?'mismatch':'success';displayMode=mode;
    await sendReset();check(resetStatus().includes('could not be displayed')&&resetCard.querySelector('code').parentElement.hidden,'invalid reset handover was exposed');
  }
  await mountSharedAccountResetIssue(resetCard,resetApi);
  answered='promise';displayMode='';await sendReset();
  const before=resetKeyDisposed;window.dispatchEvent(new Event('pagehide'));
  resolveReset({status:'issued'});await tick();
  check(resetKeyDisposed>before&&resetCard.querySelector('code').parentElement.hidden,'late reset delivery reached a retired document');
  }
  {
  const resetCard=document.createElement('section');document.body.append(resetCard);
  const first='20111111-1111-4111-8111-111111111111',second='30111111-1111-4111-8111-111111111111',
        third='40111111-1111-4111-8111-111111111111',last='50111111-1111-4111-8111-111111111111';
  const candidates=[
    {userId:first,loginName:'queue-first',eligible:true,status:'not-issued'},
    {userId:second,loginName:'queue-second',eligible:true,status:'not-issued'},
    {userId:third,loginName:'queue-waiting',eligible:true,status:'awaiting-handover',offerId:third,expiresAt:1800000000},
    {userId:last,loginName:'queue-unavailable',eligible:false,status:'not-issued'},
  ];
  const sent=[],marked=[],left=[];
  let markState='busy',loadState='ready',pageReads=0;
  const api={resetContext:async()=>resetWorkspace,close:async()=>true,
    resetTargets:async(after)=>{
      pageReads++;
      if(loadState==='error')throw Error('internal read failure');
      if(loadState!=='ready')return {status:loadState};
      return {status:'ready',page:after?{targets:candidates.slice(2)}:{targets:candidates.slice(0,2),next:second}};
    },
    markResetHandover:async mark=>{
      marked.push(mark);
      const candidate=candidates.find(account=>account.userId===mark.userId);
      check(candidate?.offerId===mark.offerId,'wrong account or offer acknowledged');
      if(markState==='handed-over'||markState==='redeemed')candidate.status=markState;
      return {status:markState};
    },
    leaveResetPending:async offer=>{left.push(offer);return true;},
    issueReset:async(value)=>{
      const candidate=candidates.find(account=>account.userId===value.targetUserId);
      check(candidate?.loginName===value.targetLogin,'queue allowed editing the selected login');
      candidate.offerId=candidate.userId;
      candidate.expiresAt=1800000000;
      candidate.status='awaiting-handover';
      sent.push(value.targetLogin);
      return {status:'issued',handover:{workspaceId:resetWorkspace,requestId:value.requestId,offerId:candidate.offerId,bundle:{}}};
    }};
  const click=async caption=>{const button=[...resetCard.querySelectorAll('button')].find(button=>button.textContent===caption);check(button&&!button.hidden,'missing reset action '+caption);button.click();await tick();};
  const send=async()=>{resetCard.querySelector('[name=target-login]').value='queue-wrong';resetCard.querySelector('[name=password]').value='fixture';resetCard.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));await tick();};
  const status=()=>resetCard.querySelector('[role=status]').textContent;
  await mountSharedAccountResetIssue(resetCard,api);
  check(resetCard.querySelector('form').hidden&&pageReads===1,'default reset mode did not load account queue');
  await click('Load more accounts');
  check(resetCard.querySelectorAll('li').length===4&&resetCard.querySelectorAll('li input')[3].disabled,'queue lost a loaded page or enabled missing recovery keys');
  await click('Select accounts that need an offer');
  check([...resetCard.querySelectorAll('li input')].map(input=>input.checked).join(',')==='true,true,false,false','bulk selection included an active offer or missing recovery keys');
  await click('Issue resets for selected accounts');
  check(resetCard.querySelector('[name=target-login]').readOnly&&status().includes('1 remaining'),'batch did not bind its first account');
  await send();
  check(sent.join(',')==='queue-first'&&status().includes('Offer issued.')&&resetCard.querySelector('h2').textContent==='Deliver to queue-first','batch did not identify the current recipient');
  await click('Mark handed over and continue');
  check(status().includes('Try again')&&resetCard.querySelector('code').textContent!=='','busy handover destroyed the presented factors');
  markState='handed-over';await click('Mark handed over and continue');
  check(resetCard.querySelector('[name=target-login]').value==='queue-second'&&resetCard.querySelector('code').textContent===''&&resetCard.querySelector('h2').textContent==='','delivered factors survived the next account');
  await send();await click('Leave pending and continue');
  check(left.join(',')===second&&sent.join(',')==='queue-first,queue-second'&&resetCard.querySelector('form').hidden,'leaving the second offer pending lost batch sequencing');
  await click('Load more accounts');
  const row=login=>[...resetCard.querySelectorAll('li')].find(item=>item.querySelector('label').textContent===login);
  markState='busy';row('queue-waiting').querySelector('button').click();await tick();
  check(status().includes('Refresh')&&row('queue-waiting').textContent.includes('Awaiting handover'),'busy confirmation lost a pending offer');
  markState='handed-over';row('queue-waiting').querySelector('button').click();await tick();
  check(row('queue-waiting').textContent.includes('Handed over')&&!row('queue-waiting').querySelector('button')&&marked.at(-1)?.offerId===third&&status()==='Handover recorded.','resumed handover could not be recorded');
  markState='redeemed';row('queue-second').querySelector('button').click();await tick();
  check(row('queue-second').textContent.includes('Redeemed')&&status().includes('already redeemed'),'handover did not reconcile a redeemed offer');
  loadState='error';await click('Refresh account list');check(status().includes('Could not load')&&!status().includes('internal'),'queue failure leaked native diagnostics');
  const selection=row('queue-first').querySelector('input');
  selection.click();selection.click();selection.click();
  loadState='unavailable';await click('Refresh account list');
  check(resetCard.querySelectorAll('li').length===0&&[...resetCard.querySelectorAll('button')].find(button=>button.textContent==='Issue resets for selected accounts').disabled,'unavailable custody left a stale account selection in the window');
  loadState='ready';await click('Refresh account list');
  check(!row('queue-first').querySelector('input').checked,'stale selections returned after restoring custody');
  row('queue-first').querySelector('input').click();
  await click('Issue resets for selected accounts');
  check(status().includes('retires this account')&&resetCard.querySelector('[type=submit]').textContent.includes('replacement'),'replacement lacked a notice');
  await click('Skip this account');
  check(sent.length===2&&resetCard.querySelector('form').hidden,'skipping a replacement issued another offer');
  window.dispatchEvent(new Event('pagehide'));
  loadState='unsupported';
  await mountSharedAccountResetIssue(resetCard,api);
  check(!resetCard.querySelector('form').hidden,'schema 53 lost the manual issue path');
  resetCard.remove();
  }
  await finishAdminPage();
}).then(async()=>{
  const check=(value,message)=>{if(!value)throw Error(message)};
  const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
  const root=document.createElement('div');document.body.append(root);
  let group, member=false, busy=false, createBusy=true, stale=false, pending, failList=true, paginate=false;
  const createIds=[];
  let reviewedKey, memberRemoval, resumeAfterReopen=false, additionStatus, rosterChanged=false, staleReconciliation=true, memberStatus='disabled';
  const resumeRequests=[];
  const dispose=mountSharedGroupAdministration(root,async request=>{
    if(pending)await new Promise(resolve=>pending=resolve);
    switch(request.action){
      case 'list':
        if(failList){failList=false;throw Error('private group diagnostic');}
        return {status:'ready',page:{entries:group&&!request.after?[group]:[],...(paginate&&group&&!request.after?{after:group.id}:{})}};
      case 'create':
        createIds.push(request.groupId);
        if(createBusy){createBusy=false;return{status:'busy'};}
        group={id:request.groupId,name:request.name,revision:'1'};
        break;
      case 'members':
        return {status:'ready',page:{entries:member&&!request.after?[{id:'person',login:'alice',status:memberStatus}]:[],...(paginate&&member&&!request.after?{after:'person'}:{})}};
      case 'rename':
        if(request.name===group.name)return{status:'unchanged'};
        group={...group,name:request.name,revision:String(Number(group.revision)+1)};break;
      case 'add-member':
        if(stale){stale=false;return{status:'stale'};}
        if(reviewedKey)return {status:'key-change-required'};
        member=true;break;
      case 'remove-member':
        if(reviewedKey)return {status:'key-change-required'};
        member=false;break;
      case 'delete': group=undefined;break;
    }
    return {status:'changed'};
  }, value=>{busy=value;}, async request=>{
    if(request.review){
      check(request.review==='reviewed'&&request.groupId===group.id,'group key confirmed a different roster');
      reviewedKey=true;
      group={...group,revision:String(Number(group.revision)+1)};
      return {status:'issued'};
    }
    return {status:'review',preview:{...request,review:'reviewed',members:[{id:'person',login:'certified-alice'}]}};
  }, async request=>{
    check(request.groupId===group.id,'rotation used a different group');
    if(request.action==='reconcile'){
      check(request.jobId===memberRemoval,'recipient review changed the originating job');
      if(!request.review)return {status:'reconcile-review',reconciliation:{...request,groupName:'Overlapping group',targetGroupId:'other',
        review:'approved-recipients',boundaries:2,members:staleReconciliation?[]:[{id:'peer',login:'certified-peer'}]}};
      check(request.review==='approved-recipients','the changed recipients were not confirmed');
      if(staleReconciliation){staleReconciliation=false;return {status:'stale'};}
      rosterChanged=false;
      return {status:'reconciled'};
    }
    if(request.action==='add'){
      check(request.login==='alice'&&request.revision===group.revision,'addition targeted the wrong account or revision');
      if(additionStatus) return {status:additionStatus};
      if(!request.review) return {status:'review-add',addition:{...request,review:'approved-addition',member:{id:'person',login:'alice'},boundaries:2}};
      check(request.review==='approved-addition'&&!member,'confirmation lost the reviewed addition');
      member=true;
      group={...group,revision:String(Number(group.revision)+1)};
      return {status:'added',receipt:{jobId:request.jobId,pending:0}};
    }
    if(request.action==='remove'){
      check(request.memberId==='person'&&request.revision===group.revision,'removal targeted the wrong member or revision');
      if(!request.review)return {status:'review',preview:{...request,review:'approved-removal',boundaries:2,remaining:[{id:'peer',login:'certified-peer'}]}};
      check(request.review==='approved-removal'&&member,'confirmation lost the reviewed request');
      memberRemoval=request.jobId;
      member=false;
      group={...group,revision:String(Number(group.revision)+1)};
      return {status:'rotated',receipt:{jobId:memberRemoval,pending:2}};
    }
    resumeRequests.push(request.jobId);
    if(!resumeAfterReopen)return {status:'pending',receipt:{jobId:memberRemoval,pending:2}};
    if(rosterChanged)return {status:'roster-changed',receipt:{jobId:memberRemoval,pending:1}};
    if(!request.jobId)return {status:'pending',receipt:{jobId:memberRemoval,pending:1}};
    return {status:'complete',receipt:{jobId:memberRemoval,pending:0}};
  });
  const submit=async(label,value)=>{
    const field=[...root.querySelectorAll('input')].find(item=>item.getAttribute('aria-label')===label);
    field.value=value;
    field.form.requestSubmit();
    await tick();await tick();
  };
  const click=async label=>{
    const button=[...root.querySelectorAll('button')].find(item=>item.textContent===label);
    check(button,'missing Groups button '+label);
    button.click();await tick();await tick();
  };
  await tick();
  check(root.textContent.includes('Could not complete')&&!root.textContent.includes('private group diagnostic'),'failure leaked diagnostic');
  await click('Refresh groups');
  check(root.textContent.includes('No groups'),'empty group state absent');
  await submit('Group name','   ');
  check(root.textContent.includes('Enter a valid group name'),'empty name crossed the bridge');
  await submit('Group name',' Operations ');
  check(root.textContent.includes('busy'),'retry detail absent');
  paginate=true;
  await submit('Group name','Operations');
  check(createIds.length===2&&createIds[0]===createIds[1],'create retry did not keep its ID');
  await click('More groups');
  check(!root.textContent.includes('Operations'),'group pagination retained old rows');
  await click('First groups page');
  await click('Operations');
  stale=true;
  await submit('Account sign-in name','alice');
  check(root.textContent.includes('group changed')&&!root.querySelector('form'),'stale edit retained an active form');
  await click('Back to groups');await click('Operations');
  await submit('Group name','Incident team');
  check(root.querySelector('h2').textContent==='Incident team','rename did not refresh selected group');
  await submit('Group name','Incident team');
  check(root.querySelector('h2').textContent==='Incident team','unchanged rename lost current group');
  await submit('Account sign-in name','alice');
  check(root.textContent.includes('alice (disabled)'),'membership row absent');
  await click('More members');
  check(!root.textContent.includes('alice'),'membership pagination retained old rows');
  await click('First members page');
  check(root.textContent.includes('alice (disabled)'),'first member page did not restore current membership');
  await click('Remove');
  check(root.textContent.includes('No members'),'membership removal did not refresh');
  await click('Delete group');
  check(root.textContent.includes('No groups'),'delete did not refresh the group list');
  memberStatus='enabled';
  await submit('Group name','Keyed group');
  await click('Keyed group');
  await submit('Account sign-in name','alice');
  await click('Review group key recipients');
  check(root.textContent.includes('certified-alice')&&!reviewedKey,'certified review issued or hid the recipients');
  await click('Issue group key');
  check(reviewedKey&&root.textContent.includes('Group encryption key issued.')&&!root.textContent.includes('certified-alice'),'key issuance retained its review');
  await click('Back to groups');await click('Keyed group');
  await click('Remove');
  await click('Review member removal');
  check(member&&!memberRemoval&&root.textContent.includes('2 shared boundaries')&&root.textContent.includes('certified-peer'),'review erased the member or hid the rotation scope');
  await click('Confirm member removal and rotate keys');
  check(!member&&memberRemoval&&resumeRequests.length===1&&resumeRequests[0]===memberRemoval&&root.textContent.includes('Some boundaries are still pending'),'a stalled worker did not leave a way to resume');
  await click('Back to groups');await click('Keyed group');
  resumeAfterReopen=true;
  rosterChanged=true;
  await click('Resume key rotation');
  await click('Review changed recipients');
  check(root.textContent.includes('Overlapping group')&&root.textContent.includes('organisation recovery'),'did not review an empty related group');
  await click('Confirm recipients and resume');
  check(rosterChanged&&root.textContent.includes('Resume rotation to review again'),'stale confirmation changed recipients or lost its recovery path');
  await click('Resume key rotation');
  await click('Review changed recipients');
  check(root.textContent.includes('certified-peer')&&root.textContent.includes('2 shared boundaries'),'did not show the exact current recipients or changed scope');
  await click('Confirm recipients and resume');
  check(!rosterChanged&&resumeRequests.length===4&&resumeRequests[1]===undefined&&resumeRequests[2]===undefined&&resumeRequests[3]===memberRemoval&&root.textContent.includes('Group key rotation complete.'),'reopened group did not reconcile and finish the original pending job');
  await click('Keyed group');
  for(const [response,message] of [
    ['rotation-pending','Finish the pending key rotation before adding a member.'],
    ['unsupported','Update the workspace schema to add a member to a keyed group.'],
    ['account-unavailable','No enabled account has that sign-in name.'],
    ['unavailable','Adding a member requires organisation custody'],
  ]){
    additionStatus=response;
    await submit('Account sign-in name','alice');
    check(!member&&root.textContent.includes(message)&&!root.textContent.includes('Confirm member addition'),'unavailable addition left a confirmation active');
  }
  additionStatus=undefined;
  await submit('Account sign-in name','alice');
  check(!member&&root.textContent.includes('Add alice.')&&root.textContent.includes('2 shared boundaries'),'addition changed membership before confirmation or hid the scope');
  additionStatus='stale';
  await click('Confirm member addition');
  check(!member&&root.textContent.includes('Review the addition again')&&!root.textContent.includes('Confirm member addition'),'expired addition kept its confirmation');
  additionStatus=undefined;
  await submit('Account sign-in name','alice');
  await click('Confirm member addition');
  check(member&&root.textContent.includes('Member added and group keys updated.'),'confirmed addition was not shown');
  memberStatus='disabled';
  await click('Back to groups');await click('Keyed group');
  await click('Remove');await click('Review member removal');
  const previouslyResumed=resumeRequests.length;
  await click('Confirm member removal and queue keys');
  check(!member&&resumeRequests.length===previouslyResumed&&root.textContent.includes('Queue any other groups'),'suspended member removal started before related groups could queue');
  await click('Resume key rotation');
  check(resumeRequests.length===previouslyResumed+1&&resumeRequests.at(-1)===memberRemoval&&root.textContent.includes('Group key rotation complete.'),'explicit resume lost the queued job');
  pending=true;
  const input=root.querySelector('input');input.value='Later';input.form.requestSubmit();
  await tick();check(busy&&root.querySelector('fieldset').disabled,'pending mutation left controls active');
  dispose();pending();await tick();
  check(!root.textContent,'disposed group view rendered a late reply');root.remove();
}).then(async()=>{
  const check=(value,message)=>{if(!value)throw Error(message)};
  const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
  const root=document.createElement('div');document.body.append(root);
  let listed=[], status='changed', change, boundaryChange, rotationChange, pending, failedCatalog=true;
  const node={id:'folder',grantRevision:'2',grantBoundary:'boundary',name:'Shared folder',kind:0};
  const dispose=mountSharedGrantAdministration(root,{
    catalog:async request=>{
      if(failedCatalog){failedCatalog=false;throw Error('internal grant diagnostic');}
      return request.after ? {nodes:[node],next:null} : {nodes:[{name:'Personal folder'}],next:{after:'cursor',epoch:'1',changeSeq:'4'}};
    },
    grant:async request=>{
      if(pending)await new Promise(resolve=>pending=resolve);
      check(request.nodeId==='folder'&&request.nodeRevision==='2','grant request lost the selected node');
      if(!Object.hasOwn(request,'mask'))return {status:'ready',page:{epoch:'1',changeSeq:'4',grants:request.after?[]:listed,...(request.kind==='group'?{redirectRequiresReveal:true}:{}),...(!request.after&&listed.length?{after:'more'}:{})}};
      change=request;
      check(request.epoch==='1'&&request.changeSeq==='4','grant request lost the reviewed snapshot');
      if(status==='changed') listed=request.mask?[{subjectId:request.subjectId??'alice',label:request.login??'Operators',mask:request.mask,revision:'2'}]:[];
      return {status};
    },
    boundary:async request=>{
      check(request.nodeId==='folder'&&request.nodeRevision==='2'&&request.boundaryId==='boundary'&&request.groupId==='operators'&&request.groupRevision==='3'&&request.mask===3,'boundary request lost its review context');
      if(!request.review)return {status:'review',preview:{...request,review:'confirmed-review',previousMask:1,members:[{login:'certified-operator'}]}};
      check(request.review==='confirmed-review','confirmation lost the prior review');
      boundaryChange=request;return {status:'changed'};
    },
    rotation:async request=>{
      check(request.nodeId==='folder'&&request.boundaryId==='boundary'&&request.groupId==='operators'&&request.groupRevision==='3'&&request.mask===0,'rotation lost the selected scope');
      if(!request.review)return {status:'review',preview:{...request,review:'rotation-review',previousMask:3,members:[]}};
      check(request.review==='rotation-review','rotation confirmation lost its reviewed revision');
      rotationChange=request;return {status:'changed'};
    },
  },async ({after})=>({status:'ready',page:after?{entries:[{id:'operators',name:'Operators',revision:'3'}]}:{entries:[{id:'other',name:'Other',revision:'2'}],after:'next'}}),()=>{});
  const press=async text=>{[...root.querySelectorAll('button')].find(b=>b.textContent===text).click();await tick();await tick()};
  await tick();
  check(root.textContent.includes('Could not load')&&!root.textContent.includes('internal grant diagnostic'),'catalog error leaked diagnostics');
  await press('Reload shared items');
  check(!root.textContent.includes('Personal folder')&&root.textContent.includes('No manageable items'),'personal target offered grants');
  await press('More shared items');await press('Shared folder');
  check(root.textContent.includes('Write implies Reveal.'),'Write implication lost');
  await press('Add grant');
  check(!change&&root.textContent.includes('Choose at least one permission'),'blank grant was submitted');
  root.querySelector('input[aria-label]').value='alice';
  root.querySelector('input[type=checkbox]').checked=true;
  status='cannot-delegate';await press('Add grant');
  check(root.textContent.includes('currently have')&&change.login==='alice'&&change.mask===1,'permission denial did not preserve account input');
  status='changed';await press('Add grant');
  check(root.textContent.includes('alice'),'added account grant missing');
  await press('More direct grants');
  check(!root.textContent.includes('alice'),'older grant page retained');
  await press('Group grants');await press('More groups');
  check(root.textContent.includes('requires Reveal on that credential.')&&!root.textContent.includes('Write implies Reveal.'),'protected edits showed the legacy grant policy');
  const picker=root.querySelector('select');picker.value='operators';
  const editor=picker.parentElement;
  editor.querySelector('input[type=checkbox]').checked=true;
  [...editor.querySelectorAll('button')].find(b=>b.textContent==='Add grant').click();
  await tick();await tick();
  check(change.kind==='group'&&change.subjectId==='operators'&&root.textContent.includes('Operators'),'group picker lost the selected group');
  await press('Save permissions');
  check(change.grantRevision==='2','existing grant was not updated by revision');
  await press('Boundary keys');
  await press('Review boundary grant');
  check(root.textContent.includes('Choose a group.')&&!boundaryChange,'missing boundary recipient entered review');
  await press('More groups');
  root.querySelector('select[aria-label="Group receiving boundary keys"]').value='operators';
  root.querySelector('select[aria-label="Boundary permissions"]').value='3';
  await press('Review boundary grant');
  check(root.textContent.includes('entire boundary')&&root.textContent.includes('Operators · View → View and Use')&&root.textContent.includes('certified-operator')&&!boundaryChange,'boundary preview hid scope or published before confirmation');
  await press('Confirm and issue boundary keys');
  check(boundaryChange&&root.textContent.includes('Boundary grant saved')&&!root.textContent.includes('certified-operator'),'issued boundary grant retained a stale review');
  await press('Back to item grants');
  await press('Rotate boundary keys');await press('More groups');
  root.querySelector('select[aria-label="Group losing boundary permissions"]').value='operators';
  await press('Review boundary rotation');
  check(!rotationChange&&root.textContent.includes('Choose the permissions'),'rotation defaulted to revoking all access');
  root.querySelector('select[aria-label="Boundary permissions"]').value='0';
  await press('Review boundary rotation');
  check(root.textContent.includes('Operators · View and Use → None')&&!rotationChange,'rotation omitted the reviewed permission change or published early');
  await press('Confirm and rotate boundary keys');
  check(rotationChange&&root.textContent.includes('Boundary grant reduced and keys rotated.'),'confirmed revocation did not rotate the roots');
  await press('Back to item grants');
  status='stale';await press('Revoke grant');
  check(root.textContent.includes('Reopen the item')&&!root.querySelector('input'),'stale edit left another mutation enabled');
  pending=true;
  const back=[...root.querySelectorAll('button')].find(b=>b.textContent==='Back to shared items');
  back.click();await tick();
  const more=[...root.querySelectorAll('button')].find(b=>b.textContent==='More shared items');
  more.click();await tick();
  [...root.querySelectorAll('button')].find(b=>b.textContent==='Shared folder').click();await tick();
  dispose();pending();await tick();
  check(!root.textContent,'a late grant page survived disposal');root.remove();
})
//# sourceURL=wormhole-vault-shared-setup-screen.js`;
    const harness = join(directory, 'screen.cjs');
    await writeFile(
      harness,
      `
const {app,BrowserWindow}=require('electron');
const assert=require('node:assert/strict');
app.setPath('userData',${JSON.stringify(directory)});
app.disableHardwareAcceleration();
app.whenReady().then(async()=>{
  const window=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,offscreen:true,backgroundThrottling:false}});
  try {
    await window.loadURL('data:text/html,<html><body></body></html>');
    const debug=window.webContents.debugger;
    debug.attach('1.3');
    await debug.sendCommand('Profiler.enable');
    await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});
    await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
    const report=await debug.sendCommand('Profiler.takePreciseCoverage');
    const script=report.result.find(entry=>entry.url==='wormhole-vault-shared-setup-screen.js');
    assert.ok(script);
    for(const name of ['mountSharedSetup','mountAdminRecovery','mountSharedBackup','mountSharedRestore','mountSharedAccountResetIssue','createAccountResetQueue','mountSharedAdministration','mountCreateSlot','mountSharedGroupAdministration','mountSharedGrantAdministration','mountAccountSuspension']){
    const mount=script.functions.find(entry=>entry.functionName===name);
    assert.ok(mount);
    const extent=mount.ranges[0];
    const ranges=script.functions.filter(entry=>entry.ranges[0].startOffset>=extent.startOffset&&entry.ranges[0].endOffset<=extent.endOffset).flatMap(entry=>entry.ranges);
    const coverage=100*ranges.filter(range=>range.count>0).length/ranges.length;
    console.log(name+': '+coverage.toFixed(2)+'% V8 blocks');
    assert.ok(coverage>=${coverageThreshold});
    }
  } finally { window.destroy(); }
  app.quit();
}).catch(error=>{console.error(error);app.exit(1)});`,
    );
    const electron = createRequire(import.meta.url)('electron') as string;
    const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
    const headless = process.platform === 'linux' && !env.DISPLAY;
    const { stdout } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env, timeout: 30_000, windowsHide: true },
    );
    assert.match(stdout, /mountAdminRecovery:/);
    assert.match(stdout, /mountSharedBackup:/);
    assert.match(stdout, /mountSharedRestore:/);
    assert.match(stdout, /mountSharedAccountResetIssue:/);
    assert.match(stdout, /createAccountResetQueue:/);
    assert.match(stdout, /mountSharedAdministration:/);
    assert.match(stdout, /mountAccountSuspension:/);
    assert.match(stdout, /mountSharedGroupAdministration:/);
    assert.match(stdout, /mountSharedGrantAdministration:/);
    t.diagnostic(stdout.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  }
});
