from flask import Flask, request
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


app = Flask(__name__)
WSO2_IS = 'https://192.168.1.16:9443'


def get_recovery_code(username):
    content_header = {"content-type": "application/json"}
    json_body = '''{
        "claims": [
            {
                "uri": "http://wso2.org/claims/username",
                "value": "''' + username + '''"
            }
        ],
        "properties": []
    }'''
    return requests.post('{}/api/users/v1/recovery/password/init'.format(WSO2_IS), auth=('admin', 'admin'),
                         headers=content_header, data=json_body, verify=False)


def request_sms(recovery_code):
    content_header = {"content-type": "application/json"}
    json_body = '''{
        "recoveryCode": "''' + recovery_code + '''",
        "channelId": "2",
        "properties": []
    }'''
    return requests.post('{}/api/users/v1/recovery/password/recover'.format(WSO2_IS), auth=('admin', 'admin'),
                         headers=content_header, data=json_body, verify=False)


def confirm(reset_code):
    content_header = {"content-type": "application/json"}
    json_body = '''{
        "confirmationCode": "''' + reset_code + '''",
        "properties": []
    }'''
    return requests.post('{}/api/users/v1/recovery/password/confirm'.format(WSO2_IS), auth=('admin', 'admin'),
                         headers=content_header, data=json_body, verify=False)


def reset(reset_code, password):
    content_header = {"content-type": "application/json"}
    json_body = '''{
        "resetCode": "''' + reset_code + '''",
        "password": "''' + password + '''",
        "properties": []
    }'''
    response = requests.post('{}/api/users/v1/recovery/password/reset'.format(WSO2_IS), auth=('admin', 'admin'),
                             headers=content_header, data=json_body, verify=False)
    if response.status_code == 200:
        # print(response.json())
        return '''<p>If successful then you'll get a text message saying "Successful Password Reset."</p>
        <p>Return to the self-service user portal: <a href="https://localhost.com:9443/myaccount">MyAccount</a>.</p>'''
    else:
        # print('Issue Resetting SMS Password. Status: ' + str(response.status_code))
        # exit(response.status_code)
        return response.json()


@app.route('/', methods=['GET', 'POST'])
def sms_password_reset():

    if request.method == 'GET':
        username = request.args.get('username')
        one_time_password = request.args.get('otp')
        if username is None or username == '':
            display = '<p>Please enter specify your username.</p><br>' + '''
                          <form action="/" method="get">
                            <label for="username">username:</label>
                            <input type="text" id="username" name="username"><br><br>
                            <input type="submit" value="Submit">
                          </form>'''
            return display
        elif one_time_password is None or one_time_password == '':
            response = get_recovery_code(username)
            if response.status_code == 200:
                recovery_code = response.json()[0]['channelInfo']['recoveryCode']
            else:
                # print('Get RecoveryCode Status: ' + str(response.status_code))
                # exit(response.status_code)
                return response.json()
            response = request_sms(recovery_code)
            if response.status_code != 202:
                # print('Issue Requesting SMS Password Recovery. Status: ' + str(response.status_code))
                # exit(response.status_code)
                display = response.json()
            else:
                display = '<h3>Hello, ' + username + '.</h3><p>Please enter the One-Time Password that was sent to your ' + \
                      'mobile device.</p><br>' + '''
                      <form action="/" method="get">
                        <input type="hidden" id="username" name="username" value="''' + username + '''"
                        <label for="otp">SMS One-Time Password:</label>
                        <input type="text" id="otp" name="otp"><br><br>
                        <input type="submit" value="Submit">
                      </form>'''

            return display
        else:
            response = confirm(one_time_password)
            display = ''
            if response.status_code == 200:
                display = '<h3>Hello, ' + username + '.</h3><p>Please enter the One-Time Password that was sent to your ' + \
                          'mobile device and specify a new password.</p><br>' + '''
                          <form action="/?set-password=true" method="post">
                            <input type="hidden" id="otp" name="otp" value="''' + one_time_password + '''">
                            <label for="pass">New Password:</label>
                            <input type="password" id="pass" name="pass"><br><br>
                            <label for="pass2">New Password:</label>
                            <input type="password" id="pass2" name="pass2" onkeyup="comparePasswords();"><br><br>
                            <p id="passMessage">The new password needs to meet your password complexity requirements.</p>
                            <input type="submit" value="Submit">
                          </form>
                          <script>
                          function comparePasswords() {
                            if (document.getElementById("pass").value == document.getElementById("pass2").value &&
                                document.getElementById("pass").value.length > 0) {
                              document.getElementById("passMessage").innerHTML = "Passwords match. Good job!";
                            } else {
                              document.getElementById("passMessage").innerHTML = "Passwords do not match. Keep trying.";
                            }
                          }
                          </script>'''
            else:
                # print('Issue Resetting SMS Password. Status: ' + str(response.status_code))
                # exit(response.status_code)
                display = response.json()
            return display
    else:
        display = reset(request.form['otp'], request.form['pass'])
        return display


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    app.run(host='0.0.0.0', port=4242)