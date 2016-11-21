import requests
import json

url='https://ec2-54-209-30-18.compute-1.amazonaws.com/submit'
# This data needs to be updated
uid = 2736475886
dbdata = json.dumps([{
    'id_': 123123,
    'isTypo': "bla",
    'oman': "pla"
}])
def test_upload():
    r = requests.post(
        url,
        data=dict(
            uid=uid,
            data=dbdata,
            test=1
        ),
        allow_redirects=True,
        verify=False
    )
    assert r.status_code == 200
    assert r.text == 'Success'

