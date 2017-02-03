import requests
import json
import hashlib
import rsa
import uuid
import re
import base64
import os
from termcolor import colored
from awsmanager import AWSManager

def color(response):
    if response.status_code==200:
        return 'green'
    else:
        return 'red'

class Device():
    def __init__(self, device_id, device_name):
        self.id = device_id
        self.name = device_name
        (pubkey, privkey) = rsa.newkeys(512)
        self.pub_key = pubkey
        self.priv_key = privkey
        self.accessToken = None
        self.base_url = ''
    def server_get_roles(self):
        url = '%scontent/roles/?accessToken=%s' % (self.base_url, self.accessToken)
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_delete_group(self, group_id):
        url = '%scontent/delete_group/?accessToken=%s&group_id=%s' % (self.base_url,
            self.accessToken,
            str(group_id))
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_confirm_role(self, role_id):
        url = '%scontent/confirm_role/?accessToken=%s&role_id=%s' % (self.base_url,
            self.accessToken,
            str(role_id))
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_confirm_all_roles(self):
        roles = self.server_get_roles().json()
        confirm_role_ids = filter(lambda r: r['is_confirmed']==False, roles['roles'])
        confirm_role_ids = map(lambda r: r['id'], confirm_role_ids)
        for rid in confirm_role_ids:
            self.server_confirm_role(rid)
    def delete_role(self, role_id):
        url = '%scontent/delete_role/?accessToken=%s&role_id=%s' % (self.base_url,
            self.accessToken,
            str(role_id))
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_delete_file(self, group_id, item_id):
        url = '%scontent/delete_file/?accessToken=%s&group_id=%s&item_id=%s' % (self.base_url,
            self.accessToken,
            str(group_id),
            str(item_id))
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_check_accesses(self):
        url = '%scontent/check_accesses/?accessToken=%s' % (self.base_url, self.accessToken)
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_get_actual_aws_info(self, hash_data):
        url = '%scontent/actual_aws_info/?accessToken=%s&hash_data=%s' % (self.base_url,
            self.accessToken,
            hash_data)
        r = requests.get(url)
        return r
    def server_upload_file(self, group_ids, raw_data, meta, item_id=None):
        size_bytes = 10000000
        url = '%scontent/add_file/?accessToken=%s&group_ids=%s&size_bytes=%i' % (self.base_url,
            self.accessToken,
            str(group_ids),
            size_bytes)
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        result = r.json()
        # print r.text
        # raise
        keys = result.get('keys')

        cyphers = {}
        secret_key = str(uuid.uuid4())

        for item in keys:
            pub_key_string = item['pub_key']
            device_id = item['device_id']
            pub_key = rsa.PublicKey.load_pkcs1(pub_key_string.decode('hex'), 'DER')
            crypto = rsa.encrypt(secret_key, pub_key)
            cyphers[device_id] = crypto.encode('hex')

        url = '%scontent/add_file/' % self.base_url
        if item_id is None:
            aws = AWSManager('AKIAIBTKZRK76AYO2QGA', 'eisav0Q3BWdFii0G+hZXq9dxDYceGM17uz+oVvZ8')
            hash_data = hashlib.sha256(raw_data).hexdigest()

            result = self.server_get_actual_aws_info(hash_data).json()
            aws_bucket = result['aws_bucket']
            aws_dir = result['aws_dir']
            aws_key = os.path.join(aws_dir, hash_data)
            aws_info = aws.upload_from_string(aws_bucket, aws_key, raw_data)
            aws_info['size_bytes'] = size_bytes
            r = requests.post(url, data={
                'accessToken': self.accessToken,
                'group_ids': str(group_ids),
                'data': raw_data,
                'metadata': meta,
                'cyphers': json.dumps(cyphers),
                'aws_data': json.dumps(aws_info),
            })
        else:
            r = requests.post(url, data={
                'accessToken': self.accessToken,
                'group_ids': str(group_ids),
                'item_id': item_id,
                'metadata': meta,
                'cyphers': json.dumps(cyphers)
            })
        print colored('POST ' + url, color(r))
        return r
    def server_add_role(self, group_id, target_email, role_type):
        url = '%scontent/add_role/?accessToken=%s&group_id=%s&target_email=%s' % (self.base_url,
            self.accessToken,
            group_id, 
            target_email)
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        result = r.json()
        
        try:
            target_devices = result['target_devices']
            my_pub_key = result['my_pub_key']
            file_keys = result['file_keys']
        except:
            print colored(result, 'red')

        pub_key_str = self.pub_key.save_pkcs1('DER').encode('hex')
        assert pub_key_str==my_pub_key, 'keys must be equels'

        cyphers = []
        for f in file_keys:
            data_item_id = f['data_item_id']
            cypher_key = f['cypher_key'].decode('hex')
            message = rsa.decrypt(cypher_key, self.priv_key)
            for td in target_devices:
                pub_key = td['pub_key']
                p_k = rsa.PublicKey.load_pkcs1(pub_key.decode('hex'), 'DER')
                cypher = rsa.encrypt(message, p_k).encode('hex')
                cyphers.append({
                    'data_item_id': data_item_id,
                    'device_id': td['device_id'],
                    'secret_key': cypher
                })


        url = '%scontent/add_role/' % self.base_url
        data = {
            'accessToken': self.accessToken,
            'group_id': group_id,
            'target_email': target_email,
            'cyphers': json.dumps(cyphers),
            'role_type': role_type
        }
        r = requests.post(url, data=data)
        print colored('POST ' + url, color(r))
        print colored(data, color(r))
        return r
    def server_get_files(self):
        url = '%scontent/files/?accessToken=%s' % (self.base_url, self.accessToken)
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_change_file(self, item_id, metadata, prev_meta_hash, data, prev_data_hash):
        url = '%scontent/change_file/' % self.base_url
        params = {
            'accessToken': self.accessToken,
            'item_id': str(item_id),
            'metadata': metadata,
            'prev_hash_meta': prev_meta_hash
        }

        if data:

            hash_data = hashlib.sha256(data).hexdigest()
            
            result = self.server_get_actual_aws_info(hash_data).json()
            aws_bucket = result['aws_bucket']
            aws_dir = result['aws_dir']
            aws = AWSManager('AKIAIBTKZRK76AYO2QGA', 'eisav0Q3BWdFii0G+hZXq9dxDYceGM17uz+oVvZ8')
            aws_key = os.path.join(aws_dir, hash_data)
            aws_info = aws.upload_from_string(aws_bucket, aws_key, data)

            params['data'] = data
            params['prev_hash_data'] = prev_data_hash
            params['aws_data'] = json.dumps(aws_info)
        r = requests.post(url, data=params)
        print colored('POST ' + url, color(r))
        return r
            

class Person():
    def __init__(self, email, password, name, base_url='http://127.0.0.1:8000/'):
        self.email = email
        self.password = password
        md5 = hashlib.md5()
        md5.update(email + 'fuck you' + password)
        self.secret = md5.hexdigest()
        self.devices = []
        self.base_url = base_url
        self.name = name
        self.accessTokens = []
    def server_delete(self):
        url = '%sauth/delete_user/?email=%s' % (self.base_url, self.email)
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_registration(self, details=''):
        url = '%sauth/registration/' % (self.base_url,)
        r = requests.post(url, data={
            'email': self.email,
            'password': self.password,
            'secret': self.secret,
            'name': self.name,
            'details': details
        })
        print colored('POST ' + url, color(r))
        return r
    def server_login(self, device):
        self.devices.append(device)
        url = '%sauth/login/?email=%s&password=%s&secret=%s&device_id=%s&pub_key=%s&device_name=%s' % (self.base_url, 
           self.email, 
           self.password, 
           self.secret,
           device.id,
           device.pub_key.save_pkcs1('DER').encode('hex'),
           device.name)
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        accessToken = r.json()['accessToken']
        self.accessTokens.append(accessToken)
        device.accessToken = accessToken
        device.base_url = self.base_url
        return r
    def server_logout(self):
        url = '%sauth/logout/?email=%s&password=%s&secret=%s' % (self.base_url,
           self.email,
           self.password,
           self.secret)
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_create_group(self, device, name):
        url = '%scontent/create_group/' % (self.base_url)
        data={
            'accessToken': self.accessTokens[-1],
            'name': name
        }
        r = requests.post(url, data=data)
        print colored('POST ' + url, color(r))
        print colored(data, color(r))
        return r
    def server_get_roles(self, device):
        url = '%scontent/roles/?accessToken=%s' % (self.base_url, self.accessTokens[-1])
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r
    def server_request_add_file(self, device, group_ids, type_tag):
        url = '%scontent/request_add_file/?accessToken=%s&group_ids=%s&type_tag=%s' % (self.base_url,
            self.accessTokens[-1],
            str(group_ids), type_tag)
        r = requests.get(url)
        print colored('GET ' + url, color(r))
        return r


