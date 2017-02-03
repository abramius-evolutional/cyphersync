from models.models import Person, Device
from termcolor import colored
import json

def run(BASE_URL):

    UA = Person('userA@xxx.com', 'Apassword', 'userA', base_url=BASE_URL)
    UB = Person('userB@xxx.com', 'Bpassword', 'userB', base_url=BASE_URL)
    UC = Person('userC@xxx.com', 'Cpassword', 'userC', base_url=BASE_URL)
    UD = Person('userD@xxx.com', '827ccb0eea8a706c4c34a16891f84e7b', 'J', base_url=BASE_URL)

    DA = Device(101, 'iphoneA')
    DB = Device(102, 'androidB')
    DC = Device(103, 'iphoneC')
    DD = Device(104, 'deviceD')

    print colored(UA.server_delete().json(), 'yellow')
    print colored(UB.server_delete().json(), 'yellow')
    print colored(UC.server_delete().json(), 'yellow')
    print colored(UD.server_delete().json(), 'yellow')

    print colored(UA.server_registration().json(), 'yellow')
    print colored(UB.server_registration().json(), 'yellow')
    print colored(UC.server_registration().json(), 'yellow')
    print colored(UD.server_registration().json(), 'yellow')

    print colored(UA.server_login(DA).json(), 'yellow')
    print colored(UB.server_login(DB).json(), 'yellow')
    print colored(UC.server_login(DC).json(), 'yellow')
    print colored(UD.server_login(DD).json(), 'yellow')

    def print_files():
        la = len(DA.server_get_files().json()['items'])
        lb = len(DB.server_get_files().json()['items'])
        lc = len(DC.server_get_files().json()['items'])
        ld = len(DD.server_get_files().json()['items'])
        print 'DA sees', la, 'files'
        print 'DB sees', lb, 'files'
        print 'DC sees', lc, 'files'
        print 'DD sees', ld, 'files'
        return [la, lb, lc, ld]

    r = UA.server_create_group(DA, 'NEW GROUP!')
    print 'Device A created new group'
    new_group = r.json()
    new_group_id = new_group['role']['group']['id']
    print colored(DA.server_add_role(new_group_id, 'userC@xxx.com', 'administrator').json(), 'yellow')
    print 'Device A add admin role for Device C'

    DC.server_confirm_all_roles()

    group_ids = json.dumps([new_group_id])
    r = DA.server_upload_file(group_ids, 'content 1', '{"type": "video"}')
    print 'UA uploaded a file'

    print colored(DC.server_add_role(new_group_id, 'userD@xxx.com', 'administrator').json(), 'yellow')
    print 'Device C add admin role for Device D'

    DD.server_confirm_all_roles()
    print 'Device D confirmed all roles'

    roles = DC.server_get_roles().json()
    role_id = roles['roles'][1]['id']
    DA.delete_role(role_id)

    counts = print_files()

    return counts == [1, 0, 1, 1]
    