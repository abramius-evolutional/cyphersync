from models.models import Person, Device
from termcolor import colored
import json

def run(BASE_URL):
    UA = Person('userA@xxx.com', 'Apassword', 'userA', base_url=BASE_URL)
    UB = Person('userB@xxx.com', 'Bpassword', 'userB', base_url=BASE_URL)

    DA = Device(101, 'iphoneA')
    DB = Device(102, 'androidB')

    print colored(UA.server_delete().json(), 'yellow')
    print colored(UB.server_delete().json(), 'yellow')

    print colored(UA.server_registration().json(), 'yellow')
    print colored(UB.server_registration().json(), 'yellow')

    print colored(UA.server_login(DA).json(), 'yellow')
    print colored(UB.server_login(DB).json(), 'yellow')

    private_role = DA.server_get_roles().json()['roles'][0]
    pr_gr_id = private_role['group']['id']
    group_ids = json.dumps([pr_gr_id])
    r = DA.server_upload_file(group_ids, 'data file 0', '{"type": "video"}')
    item_id = r.json()['item']['id']

    r = UA.server_create_group(DA, 'A and C')
    new_group = r.json()
    new_group_id = new_group['role']['group']['id']
    print colored(DA.server_add_role(new_group_id, 'userB@xxx.com', 'administrator').json(), 'yellow')
    print colored(DA.server_add_role(new_group_id, 'userB@xxx.com', 'visitor').json(), 'yellow')

    group_ids = json.dumps([new_group_id])
    r = DA.server_upload_file(group_ids, None, '{"type": "video"}', item_id)
    r = DA.server_upload_file(group_ids, 'data file 2', '{"type": "video"}')
    r = DA.server_upload_file(group_ids, 'data file 3', '{"type": "photo"}')
    r = DA.server_upload_file(group_ids, 'data file 4', '{"type": "photo"}')
    r = DA.server_upload_file(group_ids, 'data file 5', '{"type": "photo"}')

    r = DA.server_check_accesses()
    if len(r.json()['missing_cypher_accesses']) == 0:
        return True

    return False