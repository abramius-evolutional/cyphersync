from models.models import Person, Device
from termcolor import colored
import json

def run(BASE_URL):
    UA = Person('userA@xxx.com', 'Apassword', 'userAA', base_url=BASE_URL)
    UB = Person('userB@xxx.com', 'Bpassword', 'userBB', base_url=BASE_URL)

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

    r = UA.server_create_group(DA, 'NEW GROUP FOR DELETE')
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

    r = DA.server_delete_file(pr_gr_id, item_id)
    pr_gr_id_B = DB.server_get_roles().json()['roles'][0]['group']['id']
    r = DB.server_upload_file(json.dumps([pr_gr_id_B]), None, '{"type": "video"}', item_id)
    r = DA.server_delete_file(new_group_id, item_id)

    roles_new_group = DA.server_get_roles().json()['roles'][1]
    r = DA.delete_role(roles_new_group['id'])

    roles_new_group = DB.server_get_roles().json()['roles'][1]
    print DB.server_get_roles().text
    r = DB.delete_role(roles_new_group['id'])

    DB.server_confirm_all_roles()

    la = len(DA.server_get_files().json()['items'])
    lb = len(DB.server_get_files().json()['items'])

    if (la==0) & (lb==1):
        return True

    return False