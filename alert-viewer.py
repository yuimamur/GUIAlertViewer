# -*- mode: python ; coding: utf-8 -*-
import PySimpleGUI as sg
import requests
import json
import datetime
import time

def detection_edr(username,password,server):
    port = "443"
    data = {
        "username": username,
        "password": password,
    }
    headers = {"Content-Type": "application/json"}
    base_url = "https://" + server + ":" + port
    login_url = base_url + "/login.html"
    session = requests.session()
    response = session.post(login_url, data=data, verify=True)

    endpoint_url = "/rest/detection/inbox"
    api_url = base_url + endpoint_url

    date_formatted_start = datetime.datetime.strptime(values['開始'], "%Y/%m/%d")
    date_formatted_end = datetime.datetime.strptime(values['終了'], "%Y/%m/%d")

    epoch_start = int(time.mktime(date_formatted_start.timetuple()) * 1000)
    epoch_end = int(time.mktime(date_formatted_end.timetuple()) * 1000)
    start_time = epoch_start
    end_time = epoch_end
    query = json.dumps({"startTime":start_time,"endTime":end_time})
    api_headers = {'Content-Type':'application/json'}
    api_response = session.request("POST", api_url, data=query, headers=api_headers)
    your_response = json.loads(api_response.content)

    malop_detection_type = [];
    c2_domain = [];
    machine_name_list = [];
    malops = your_response['malops']

    detection_type1= 'EDR'

    edr = 0
    for i in range(len(malops)):
          malop_detection_type.append(malops[i]['detectionEngines'])
          if (detection_type1) in malop_detection_type[i]:
                c2_domain.append(malops[i]['machines'])
                edr += 1
                for machine in c2_domain:
                    machine_name_list.append(machine[0]['displayName'])
    machine_name = list(set(machine_name_list))
    return machine_name,edr

sg.theme('SandyBeach')
frame1 = sg.Frame('Simple App',
[
    [sg.Text('Server',font=('メイリオ',18),size=(15, 0)),sg.InputText('',font=('メイリオ',15))],
    [sg.Text('Username',font=('メイリオ',18), size=(15, 0)), sg.InputText('',font=('メイリオ',15))],
    [sg.Text('Password',font=('メイリオ',18),  size=(15, 0)), sg.InputText('',font=('メイリオ',15),password_char="*")],
    [sg.Text('開始:',font=('メイリオ',18), size=(15, 0)),sg.I(key='開始', size=(13,2),font=('メイリオ',15)),sg.CalendarButton('日付選択',font=('メイリオ',15),
                month_names=[ "{:>2d}月".format(m) for m in range(1, 13) ],
                format='%Y/%m/%d',
                locale='en_US',
                key='-button_calendar-',
                target='開始')],
    [sg.Text('終了:',font=('メイリオ',18), size=(15, 0)), sg.I(key='終了', size=(13,2),font=('メイリオ',15)), sg.CalendarButton('日付選択',font=('メイリオ',15),
                month_names=["{:>2d}月".format(m) for m in range(1, 13)],
                format='%Y/%m/%d',
                locale='en_US',
                key='-button_calendar-',
                target='終了')],
    [sg.Submit(button_text='実行',font=('メイリオ',15),size=(50, 0),pad=((10, 5), (50, 0)))],
],font=('メイリオ',20),size=(500, 700)
)

frame2 = sg.Frame('実行結果',
    [
        [
            sg.MLine(font=('メイリオ',17), size=(80,60), key='-OUTPUT-'),
        ],
    ] ,font=('メイリオ',20), size=(500, 700),
)

layout = [
    [
        frame1,
        frame2,
    ]
]

window = sg.Window('Simple App', layout,grab_anywhere=True,resizable=True)

while True:
    event, values = window.read()

    if event is None:
        print('exit')
        break

    if event == '実行':
        show_message = "サーバ環境：" + values[0] + '\n'
        show_message += '\n'
        malicious_domain = [];
        malicious_domain.append(detection_edr(values[1], values[2], values[0]))
        malicious_domain_new = malicious_domain[0][0]
        show_message += values['開始'] + ' から '+ values['終了'] + f' までの期間の中で {malicious_domain[0][1]}件 のEDRアラートを確認しました\n'
        show_message += '\n' + '【端末名】\n'
        for i in malicious_domain_new:
            show_message += '● ' + i + '\n'
        window.FindElement('-OUTPUT-').Update(show_message)
window.close()
