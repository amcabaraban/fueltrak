// Externalized reports page JS (moved from public/reports.html)
document.querySelector('#sidebar a[href="/reports"]').style.background = '#1e40af';
const API='/api';const token=localStorage.getItem('fueltrak_token');const user=JSON.parse(localStorage.getItem('fueltrak_user')||'{}');
if(!token||!['dispatcher','management'].includes(user.role))window.location.replace('/');
document.getElementById('userInfo').textContent=user.email.split('@')[0].substring(0,3)+'***@'+user.email.split('@')[1]+' ('+user.role+')';
async function api(url,method='GET'){const r=await fetch(API+url,{method,headers:{'Authorization':'Bearer '+token}});return await r.json()}
async function loadFilters(){const d=await api('/reports/filters');if(d.status==='success'){document.getElementById('clientFilter').innerHTML='<option value="">All</option>'+d.data.clients.map(c=>`<option value="${c.id}">${c.label}</option>`).join('');document.getElementById('truckFilter').innerHTML='<option value="">All</option>'+d.data.trucks.map(t=>`<option value="${t.id}">${t.label}</option>`).join('')}document.getElementById('startDate').value=new Date().toISOString().split('T')[0];document.getElementById('endDate').value=new Date().toISOString().split('T')[0]}
var currentPage=1,recordsPerPage=15,allRecords=[];
function paginateData(){var tp=Math.ceil(allRecords.length/recordsPerPage);if(currentPage>tp)currentPage=tp||1;var s=(currentPage-1)*recordsPerPage,pd=allRecords.slice(s,s+recordsPerPage);renderTableRows(pd);var h='<button onclick="changePage('+(currentPage-1)+')" class="px-2 py-1 border rounded '+(currentPage===1?'text-gray-300':'hover:bg-gray-100')+'" '+(currentPage===1?'disabled':'')+'><i class="fas fa-chevron-left"></i></button>';for(var i=1;i<=tp;i++){if(i===1||i===tp||(i>=currentPage-2&&i<=currentPage+2))h+='<button onclick="changePage('+i+')" class="px-2 py-1 border rounded '+(i===currentPage?'bg-blue-900 text-white':'hover:bg-gray-100')+'">'+i+'</button>';else if(i===currentPage-3||i===currentPage+3)h+='<span class="px-1">...</span>'}h+='<button onclick="changePage('+(currentPage+1)+')" class="px-2 py-1 border rounded '+(currentPage===tp?'text-gray-300':'hover:bg-gray-100')+'" '+(currentPage===tp?'disabled':'')+'><i class="fas fa-chevron-right"></i></button>';document.getElementById('pagination').innerHTML=h}
function changePage(p){if(p<1||p>Math.ceil(allRecords.length/recordsPerPage))return;currentPage=p;paginateData()}
function renderTableRows(records){
    var html = records.map(r=>{
        var cancelReason = '-';
        var cancelledBy = '-';
        if (r.status === 'cancelled' || r.status === 'rejected') {
            cancelReason = r.remarks || 'No reason provided';
            if (r.remarks && r.remarks.includes('Cancellation:')) {
                cancelledBy = '<span class="bg-blue-100 text-blue-800 px-1.5 py-0.5 rounded text-xs font-semibold">Client</span>';
            } else if (r.verified_by) {
                cancelledBy = '<span class="bg-purple-100 text-purple-800 px-1.5 py-0.5 rounded text-xs font-semibold">Dispatcher</span>';
            } else if (r.status === 'rejected') {
                cancelledBy = '<span class="bg-purple-100 text-purple-800 px-1.5 py-0.5 rounded text-xs font-semibold">Dispatcher</span>';
            } else {
                cancelledBy = '<span class="bg-gray-100 text-gray-800 px-1.5 py-0.5 rounded text-xs">System</span>';
            }
            cancelReason = cancelReason.replace('Cancellation: ', '');
            if (cancelReason.length > 40) cancelReason = cancelReason.substring(0, 40) + '...';
        }
        return `<tr class="border-b hover:bg-gray-50">
                <td>${r.completed_date?new Date(r.completed_date).toLocaleDateString():r.dispatch_date?new Date(r.dispatch_date).toLocaleDateString():r.scheduled_date?new Date(r.scheduled_date).toLocaleDateString():'-'}</td>
                <td class="font-mono font-bold text-blue-900">${r.atl_code||'-'}</td>
                <td class="cursor-pointer hover:bg-yellow-50" onclick="editSO(${r.id},this)">${r.so_number||'-'}</td>
                <td>${r.company||'-'}</td>
                <td class="font-semibold">${r.plate_no}</td>
                <td>${r.driver_name||'-'}</td>
                <td>${r.hauler||'-'}</td>
                <td>${r.contact_number||'-'}</td>
                <td class="text-right">${r.volume?Math.round(r.volume).toLocaleString():'0'}</td>
                <td class="text-right">${r.actual_volume?Math.round(r.actual_volume).toLocaleString():'-'}</td>
                <td class="text-center cursor-pointer hover:bg-blue-50" onclick="toggleSI(${r.id},this)">${r.has_si==1?'Yes':'No'}</td>
                <td class="text-center"><span class="px-1 py-0.5 rounded text-xs font-semibold ${r.status==='completed'?'bg-green-100 text-green-800':r.status==='cancelled'?'bg-red-100 text-red-800':r.status==='rejected'?'bg-red-100 text-red-800':'bg-orange-100 text-orange-800'}">${r.status}</span></td>
                <td class="text-xs max-w-[150px] truncate" title="${cancelReason !== '-' ? cancelReason.replace(/"/g,'&quot;') : ''}">${cancelReason}</td>
                <td class="text-center">${cancelledBy}</td>
                <td class="text-center cursor-pointer hover:bg-yellow-50 font-mono" onclick="editWC(${r.id},this)">${r.printed_wc||'-'}</td>
                <td class="text-center font-mono"><input id="tps_from_${r.id}" value="${r.tps_start||''}" onchange="updateTPS(${r.id},'start',this.value)" class="w-16 border rounded px-1 text-xs"></td>
                <td class="text-center font-mono"><input id="tps_to_${r.id}" value="${r.tps_end||''}" onchange="updateTPS(${r.id},'end',this.value)" class="w-16 border rounded px-1 text-xs"></td>
                <td class="text-center">${r.backload_count>0?`<span class="bg-orange-100 text-orange-800 px-1 rounded text-xs" title="${r.backload_volume||0}L">${r.backload_count}</span>`:'0'}</td>
                <td class="text-center"><button onclick="openBackload(${r.id})" class="text-orange-600"><i class="fas fa-undo"></i></button></td>
            </tr>`;
    }).join('');
    for(var i=records.length; i<10; i++){ html += '<tr style="height:35px"><td colspan="19">&nbsp;</td></tr>';}    
    document.getElementById('reportTableBody').innerHTML = html || '<tr><td colspan="19" class="text-center py-8 text-gray-500">No records found</td></tr>';
    document.getElementById('reportCount').textContent = 'Showing ' + records.length + ' of ' + allRecords.length;
}
async function editSO(id,cell){const v=prompt('SO Number:',cell.textContent.trim()==='-'?'':cell.textContent.trim());if(v===null)return;const r=await fetch('/api/dispatch/update-so/'+id,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({so_number:v})});if((await r.json()).status==='success'){cell.textContent=v||'-';cell.classList.add('bg-green-100');setTimeout(()=>cell.classList.remove('bg-green-100'),1000);}}
async function loadReports(){if(!document.getElementById('startDate').value)document.getElementById('startDate').value=new Date().toISOString().split('T')[0];if(!document.getElementById('endDate').value)document.getElementById('endDate').value=new Date().toISOString().split('T')[0];const p=new URLSearchParams();['startDate','endDate'].forEach(id=>{const v=document.getElementById(id).value;if(v)p.append(id,v)});const st=document.getElementById('statusFilter').value;if(st)p.append('status',st);const cl=document.getElementById('clientFilter').value;if(cl)p.append('clientId',cl);const tr=document.getElementById('truckFilter').value;if(tr)p.append('truckId',tr);const d=await api('/reports/summary?'+p.toString());if(d.status==='success'){const s=d.data.summary;document.getElementById('summaryCards').innerHTML=`<div class="bg-white rounded-xl shadow p-3 text-center"><p class="text-xl font-bold">${s.total_records||0}</p><p class="text-xs text-gray-500">Records</p></div><div class="bg-green-50 rounded-xl shadow p-3 text-center"><p class="text-xl font-bold text-green-700">${s.completed||0}</p><p class="text-xs text-gray-500">Completed</p></div><div class="bg-red-50 rounded-xl shadow p-3 text-center"><p class="text-xl font-bold text-red-700">${s.cancelled||0}</p><p class="text-xs text-gray-500">Cancelled</p></div><div class="bg-orange-50 rounded-xl shadow p-3 text-center"><p class="text-xl font-bold text-orange-700">${((s.total_volume||0)/1000).toFixed(1)}kL</p><p class="text-xs text-gray-500">Total Vol</p></div><div class="bg-blue-50 rounded-xl shadow p-3 text-center"><p class="text-xl font-bold text-blue-700">${((s.total_actual_volume||0)/1000).toFixed(1)}kL</p><p class="text-xs text-gray-500">Actual</p></div>`;allRecords=d.data.records||[];currentPage=1;paginateData()}}
async function updateTPS(id, field, val) {
    if (val.startsWith('=')) {
        var formula = val.substring(1);
        var fromEl = document.getElementById('tps_from_' + id);
        var toEl = document.getElementById('tps_to_' + id);
        var fromVal = fromEl ? fromEl.value : '0';
        var toVal = toEl ? toEl.value : '0';
        formula = formula.replace(/from/i, fromVal || '0');
        formula = formula.replace(/to/i, toVal || '0');
        try {
            var result = eval(formula);
            if (!isNaN(result)) {
                val = String(Math.floor(result)).padStart(fromVal.length || 3, '0');
                if (field === 'start') { if (toEl) toEl.value = val; }
                else { if (fromEl) fromEl.value = val; }
            }
        } catch(e) { console.error('Formula error:', e); }
    }
    var body = {};
    body[field === 'start' ? 'tps_start' : 'tps_end'] = val;
    await fetch('/api/dispatch/update-tps/' + id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify(body)
    });
}
function clearFilters(){['startDate','endDate','clientFilter','truckFilter'].forEach(id=>document.getElementById(id).value='');document.getElementById('startDate').value=new Date().toISOString().split('T')[0];document.getElementById('endDate').value=new Date().toISOString().split('T')[0];document.getElementById('statusFilter').value='completed,cancelled,dispatched';loadReports()}
function printReport(){window.print()}
async function exportCSV(){const p=new URLSearchParams();['startDate','endDate'].forEach(id=>{const v=document.getElementById(id).value;if(v)p.append(id,v)});const st=document.getElementById('statusFilter').value;if(st)p.append('status',st);const r=await fetch(API+'/reports/export?'+p.toString(),{headers:{'Authorization':'Bearer '+token}});if(!r.ok)return alert('Export failed');const b=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='report-'+new Date().toISOString().split('T')[0]+'.csv';a.click()}
async function editWC(id,cell){const w=prompt('Printed WC:',cell.textContent.trim()==='-'?'':cell.textContent.trim());if(w===null)return;const c=w.replace(/\D/g,'').substring(0,12);const r=await fetch('/api/dispatch/update-wc/'+id,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({printed_wc:c||null})});if((await r.json()).status==='success'){cell.textContent=c||'-';cell.classList.add('bg-green-100');setTimeout(()=>cell.classList.remove('bg-green-100'),1000)}}
async function toggleSI(id,cell){const n=cell.textContent.trim()!=='Yes';const r=await fetch('/api/dispatch/update-si/'+id,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({has_si:n?1:0})});if((await r.json()).status==='success'){cell.textContent=n?'Yes':'No';cell.classList.add('bg-green-100');setTimeout(()=>cell.classList.remove('bg-green-100'),1000)}}
function openBackload(id){document.getElementById('backloadAtlId').value=id;const row=event.target.closest('tr');document.getElementById('backloadAtlCode').value=row?row.cells[1].textContent.trim():'N/A';document.getElementById('backloadVolume').value='';document.getElementById('backloadReason').value='';document.getElementById('backloadModal').classList.remove('hidden')}
async function submitBackload(e){e.preventDefault();const id=document.getElementById('backloadAtlId').value,v=document.getElementById('backloadVolume').value,rs=document.getElementById('backloadReason').value;if(!confirm('Record backload of '+Number(v).toLocaleString()+' L?\n\nReason: '+rs))return;const r=await fetch('/api/backloads',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({atl_id:id,volume:v,reason:rs})});const d=await r.json();if(d.status==='success'){alert('Backload recorded!');document.getElementById('backloadModal').classList.add('hidden');loadReports()}else alert(d.error||'Error')}
function sortTable(tid,ci){const tb=document.getElementById(tid);if(!tb)return;const rows=Array.from(tb.querySelectorAll('tr'));if(!rows.length)return;const th=tb.closest('table').querySelectorAll('th')[ci];if(!th)return;const ia=th.classList.contains('sort-asc');tb.closest('table').querySelectorAll('th').forEach(t=>t.classList.remove('sort-asc','sort-desc'));rows.sort((a,b)=>{const av=(a.cells[ci]?.textContent||'').trim().replace(/[,%$]/g,''),bv=(b.cells[ci]?.textContent||'').trim().replace(/[,%$]/g,''),an=parseFloat(av),bn=parseFloat(bv);if(!isNaN(an)&&!isNaN(bn))return ia?bn-an:an-bn;return ia?bv.localeCompare(av):av.localeCompare(bv)});th.classList.add(ia?'sort-desc':'sort-asc');rows.forEach(r=>tb.appendChild(r))}
var currentChatUser=null,currentChatName='',chatInterval=null,contactList=[];
async function openChat(){document.getElementById('chatWidget').classList.remove('hidden');document.getElementById('chatButton').classList.add('hidden');loadContactList();}
function showContactList(){document.getElementById('contactList').classList.remove('hidden');document.getElementById('chatBody').classList.add('hidden');document.getElementById('chatInputArea').classList.add('hidden');document.getElementById('chatTitle').textContent='Chat';currentChatUser=null;loadContactList();}
async function loadContactList(){var r=await fetch('/api/chat-list',{headers:{'Authorization':'Bearer '+token}});var d=await r.json();if(d.status==='success'){contactList=d.data;var h='';contactList.forEach(function(c){h+='<div onclick="startChat('+c.id+',\''+(c.company_name||c.email)+'\')" class="flex items-center p-3 hover:bg-gray-50 cursor-pointer border-b"><div class="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center mr-3"><i class="fas fa-user text-blue-600 text-sm"></i></div><div class="flex-1"><p class="text-sm font-semibold">'+(c.company_name||c.email)+'</p><p class="text-xs text-gray-400">'+(c.email||'')+'</p></div><div class="w-2 h-2 bg-green-400 rounded-full" title="Online"></div></div>'});document.getElementById('contactList').innerHTML=h||'<p class="p-3 text-center text-gray-400 text-sm">No contacts</p>';} }
function startChat(id,name){currentChatUser=id;currentChatName=name;document.getElementById('chatTitle').textContent=name;document.getElementById('contactList').classList.add('hidden');document.getElementById('chatBody').classList.remove('hidden');document.getElementById('chatInputArea').classList.remove('hidden');loadChatMessages();if(chatInterval)clearInterval(chatInterval);chatInterval=setInterval(loadChatMessages,10000);}
async function loadChatMessages(){if(!currentChatUser)return;var r=await fetch('/api/chat/'+currentChatUser,{headers:{'Authorization':'Bearer '+token}});var d=await r.json();if(d.status==='success'){var h='';d.data.forEach(function(m){var isMe=m.sender_id==user.id;h+='<div class="'+(isMe?'text-right':'text-left')+' mb-2"><div class="inline-block '+(isMe?'bg-blue-100':'bg-gray-100')+' rounded-lg px-3 py-1.5 text-sm max-w-[80%]"><p class="text-[10px] text-gray-500">'+(isMe?'You':currentChatName)+'</p><p>'+m.message+'</p><p class="text-[9px] text-gray-400 text-right">'+new Date(m.created_at).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})+'</p></div></div>'});document.getElementById('chatBody').innerHTML=h||'<p class="text-center text-gray-400 text-sm pt-10">Start the conversation!</p>';document.getElementById('chatBody').scrollTop=document.getElementById('chatBody').scrollHeight;} }
async function sendChat(){var i=document.getElementById('chatInput');var m=i.value.trim();if(!m||!currentChatUser)return;i.value='';await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({receiver_id:currentChatUser,message:m})});loadChatMessages();}
function closeChat(){document.getElementById('chatWidget').classList.add('hidden');document.getElementById('chatButton').classList.remove('hidden');}
function openCalc(){document.getElementById('calcWidget').classList.remove('hidden');document.getElementById('calcButton').classList.add('hidden');}
function closeCalc(){document.getElementById('calcWidget').classList.add('hidden');document.getElementById('calcButton').classList.remove('hidden');}
function toggleCalc(){}
var calcExpr='';function calcInput(v){calcExpr+=v;document.getElementById('calcDisplay').value=calcExpr;}function calcClear(){calcExpr='';document.getElementById('calcDisplay').value='0';}function calcResult(){try{var r=eval(calcExpr.replace(/×/g,'*').replace(/÷/g,'/').replace(/-/g,'-'));document.getElementById('calcDisplay').value=Number(r.toFixed(4));calcExpr=String(r);}catch(e){document.getElementById('calcDisplay').value='Error';calcExpr='';}}
document.addEventListener('keydown',function(e){if(document.getElementById('calcWidget').classList.contains('hidden'))return;var k=e.key;if(k>='0'&&k<='9')calcInput(k);else if(k==='.')calcInput('.');else if(k==='+')calcInput('+');else if(k==='-')calcInput('-');else if(k==='*')calcInput('*');else if(k==='/'){e.preventDefault();calcInput('/');}else if(k==='Enter')calcResult();else if(k==='Escape')closeCalc();else if(k==='Backspace'){calcExpr=calcExpr.slice(0,-1);document.getElementById('calcDisplay').value=calcExpr||'0';}});
async function logout(){try{await fetch('/api/auth/logout',{method:'POST',headers:{'Authorization':'Bearer '+localStorage.getItem('fueltrak_token')}})}catch(e){}localStorage.clear();window.location.href='/'}
loadFilters();loadReports();
