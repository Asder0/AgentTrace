from agentdojo.method.visualization import mock_apps
tasks = mock_apps.get_original_user_tasks()
for key in ['banking::user_task_12', 'workspace::user_task_12']:
    info = tasks.get(key)
    if info:
        print(key, '| cross_app=', info.get('cross_app'), '| suite=', info.get('suite'))
        print('prompt:', info.get('prompt'))
