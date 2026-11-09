from .registry import RULES
from .behavior import is_temporary
from ..models import Detection


def privileged_group(evidence):
    sid = evidence.get('group_sid')
    name = evidence.get('group_name')
    sid = sid if isinstance(sid,str) else ''
    name = name.casefold() if isinstance(name,str) else ''
    return sid in {'S-1-5-32-544','S-1-5-32-555'} or (sid.startswith('S-1-5-21-') and sid.endswith(('-512','-519'))) or name in {'administrators','domain admins','enterprise admins','remote desktop users'}


def evaluate_persistence(event):
    if event.event_type == 'security_change':
        keys = ['HIDS-PER-004'] if event.action == 'group_member_added' and privileged_group(event.evidence) else []
    else:
        kind = event.metadata.get('kind') or event.evidence.get('kind')
        path = (event.file_path or '').replace('\\','/').lower()
        if kind == 'scheduled_task': key = 'HIDS-PER-003'
        elif kind == 'registry' or '/start menu/programs/startup/' in path: key = 'HIDS-PER-005'
        elif kind == 'service': key = 'HIDS-PER-010'
        elif path.startswith(('/etc/cron','/var/spool/cron')): key = 'HIDS-PER-006'
        elif '/systemd/' in path: key = 'HIDS-PER-011' if path.endswith('.timer') else 'HIDS-PER-007'
        elif path.endswith('/authorized_keys'): key = 'HIDS-PER-008'
        elif path.rsplit('/',1)[-1] in {'.bashrc','.profile','.zshrc','.bash_profile'}: key = 'HIDS-PER-009'
        else: key = 'HIDS-PER-001'
        keys = [key]
        if is_temporary(event.metadata.get('target_path')):
            keys.append('HIDS-PER-002')
    return [Detection.create(rule_id=key,rule_name=RULES[key].name,category='persistence',tactic=RULES[key].tactic,
        technique_id=RULES[key].technique_id,severity=RULES[key].severity,confidence=RULES[key].confidence,
        timestamp=event.timestamp,event_ids=(event.event_id,),reason=f'{RULES[key].name}: {event.action}',
        evidence={**event.evidence,'file_path':event.file_path,'target_path':event.metadata.get('target_path'), 'username':event.username},
        investigation='Verify authorized administration and compare previous/current metadata. File and registry contents are not stored.',host_id=event.host_id) for key in keys]
