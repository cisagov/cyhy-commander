#!/usr/bin/env py.test -v

import nessus
import pytest
import datetime
import time

USER = "cap-scanner"
PASSWORD = "***REMOVED***"
URL = 'https://localhost:8834'
PORTS = [80]
TARGETS = ['173.66.73.61']
BASE_POLICY_NAME = 'cyhy-base'
COPIED_POLICY_NAME = 'Copy of %s' % (BASE_POLICY_NAME)
NOW = datetime.datetime.now().isoformat()
NEW_POLICY_NAME = 'Unit Test Policy %s' % (NOW)
NEW_SCAN_NAME = 'Unit Test Scan %s' % (NOW)

@pytest.fixture
def controller():
    return nessus.NessusController(URL)
    
@pytest.fixture
def authenticated_controller():
    controller = nessus.NessusController(URL)
    controller.login(USER, PASSWORD)
    return controller

def test_good_login(controller):
    token = controller.login(USER, PASSWORD)
    assert token != None
    print 'token:', token
    
def test_bad_login(controller):
    with pytest.raises(Warning):
        token = controller.login(USER, PASSWORD[::-1])
        
def test_policy_list(authenticated_controller):
    policies = authenticated_controller.policy_list()
    for k, v in policies.iteritems():
        print k,v
        
def test_find_policy(authenticated_controller):
    policy_id = authenticated_controller.find_policy(BASE_POLICY_NAME)
    assert policy_id != None
    print BASE_POLICY_NAME, '=', policy_id
    
def test_copy_policy(authenticated_controller):
    policy_id = authenticated_controller.find_policy(BASE_POLICY_NAME)
    assert policy_id != None, 'Could not find "%s"' % (BASE_POLICY_NAME)
    policy_copy_id = authenticated_controller.policy_copy(policy_id)
    assert policy_copy_id != None, 'No policy id returned'
    assert policy_copy_id != policy_id, 'Policy copy has the same id as the source policy'
    
def test_edit_policy(authenticated_controller):
    policy_id = authenticated_controller.find_policy(COPIED_POLICY_NAME)
    assert policy_id != None, 'Could not find "%s"' % (COPIED_POLICY_NAME)
    ports = ','.join(str(port) for port in PORTS)
    changes = nessus.getPolicyChanges(ports)
    print 'editing policy', policy_id
    result = authenticated_controller.policy_edit(policy_id, NEW_POLICY_NAME, changes)
    print 'result policy id:', result
    assert result, 'Unexpected return from edit list'

def test_scan_new(authenticated_controller):
    global scan_uuid
    policy_id = authenticated_controller.find_policy(NEW_POLICY_NAME)
    assert policy_id != None, 'Could not find "%s"' % (NEW_POLICY_NAME)
    targets = ','.join(TARGETS)
    print 'Creating scan using policy_id', policy_id
    uuid = authenticated_controller.scan_new(targets, policy_id, NEW_SCAN_NAME)
    assert uuid, 'UUID was empty'
    print 'Scan UUID:', uuid
    scan_uuid = uuid
    
def test_report_list(authenticated_controller):
    scans = authenticated_controller.report_list()
    for k, v in scans.iteritems():
        print k,v
        
def test_scan_running(authenticated_controller):
    global scan_uuid
    found = False
    while authenticated_controller.scan_running(scan_uuid):
        print 'Scan running:', scan_uuid
        found = True
        time.sleep(5)
    print 'Scan not found'
    assert found, 'Scan was never seen: %s' % (scan_uuid)

def test_report_download(authenticated_controller):
    global scan_uuid
    report = authenticated_controller.report_download(scan_uuid)
    assert report, 'Report was empty'
    print report
    
def test_report_delete(authenticated_controller):
    global scan_uuid
    result = authenticated_controller.report_delete(scan_uuid)
    assert result == scan_uuid, 'Result of report delete did not match scan UUID' 
    
def test_delete_policy(authenticated_controller):
    policy_id = authenticated_controller.find_policy(NEW_POLICY_NAME)
    assert policy_id != None, 'Could not find "%s"' % (NEW_POLICY_NAME)
    result = authenticated_controller.policy_delete(policy_id)
    assert result == policy_id, 'Unexpected return from delete'
    
    


