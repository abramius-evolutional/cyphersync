from models.models import Person, Device
from termcolor import colored

def run(BASE_URL):

    userA = Person('iphoneAupload@xxx.com', 'Apassword', 'iphoneAupload@xxx.com', base_url=BASE_URL)
    userB = Person('iphoneBupload@xxx.com', 'Bpassword', 'iphoneBupload@xxx.com', base_url=BASE_URL)
    userC = Person('iphoneCupload@xxx.com', 'Cpassword', 'iphoneCupload@xxx.com', base_url=BASE_URL)

    iphoneA = Device(101, 'iphoneAupload')
    androidB = Device(102, 'androidBupload')
    iphoneC = Device(103, 'iphoneCupload')

    print colored(userA.server_delete().json(), 'yellow')
    print colored(userB.server_delete().json(), 'yellow')
    print colored(userC.server_delete().json(), 'yellow')

    print colored(userA.server_registration(details='pair of keys').json(), 'yellow')
    print colored(userB.server_registration().json(), 'yellow')
    print colored(userC.server_registration().json(), 'yellow')

    print colored(userA.server_login(iphoneA).json(), 'yellow')
    print colored(userB.server_login(androidB).json(), 'yellow')
    print colored(userC.server_login(iphoneC).json(), 'yellow')

    # print userA.server_get_roles(iphoneA).text
    new_group = userA.server_create_group(iphoneA, 'creating group!!!!!').json()
    new_group_id = new_group['role']['group']['id']

    r = userA.server_get_roles(iphoneA)

    admin_group_ids = filter(lambda r: r['role_type']=='administrator', r.json()['roles'])
    admin_group_ids = map(lambda r: r['group']['id'], admin_group_ids)

    # print userA.server_get_roles(iphoneA).text

    print colored(iphoneA.server_add_role(new_group_id, 'iphoneBupload@xxx.com', 'administrator').json(), 'yellow')
    print colored(androidB.server_add_role(new_group_id, 'iphoneCupload@xxx.com', 'reader').json(), 'yellow')

    # print userA.server_get_roles(iphoneA).text

    iphoneA.server_upload_file(admin_group_ids, 'xcontent 1', '{"uploadtype": "video"}')
    iphoneA.server_upload_file(admin_group_ids, 'xcontent 2', '{"uploadtype": "photo"}')
    iphoneA.server_upload_file(admin_group_ids, 'xcontent 3', '{"uploadtype": "photo"}')

    print colored(len(androidB.server_get_files().json()['items']), 'yellow')
    print colored(len(iphoneA.server_get_files().json()['items']), 'yellow')

    roles = userB.server_get_roles(androidB).json()
    confirm_role_ids = filter(lambda r: r['is_confirmed']==False, roles['roles'])
    confirm_role_ids = map(lambda r: r['id'], confirm_role_ids)
    for rid in confirm_role_ids:
        print colored(androidB.server_confirm_role(rid).json(), 'yellow')

    data = 'string!'
    print colored(androidB.server_upload_file([new_group_id], data, '{"type": "photo"}').json(), 'yellow')

    print colored(len(androidB.server_get_files().json()['items']), 'yellow')
    print colored(len(iphoneC.server_get_files().json()['items']), 'yellow')

    print colored(len(androidB.server_get_files().json()['items']), 'yellow')
    print colored(len(iphoneA.server_get_files().json()['items']), 'yellow')

    print len(iphoneA.server_get_files().json()['items'])
    if len(iphoneA.server_get_files().json()['items']) != 4:
        return False

    # print colored(iphoneA.server_delete_group(new_group_id).json(), 'yellow')
    # if len(iphoneA.server_get_files().json()['items']) != 3:
    #     return False
    return True