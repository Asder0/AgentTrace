# 在项目根目录 D:\AgentDojo\agentdojo 下执行
conda activate agent
python -m agentdojo.method.visualization.server

# 另外打开浏览器访问由 Flask 同源托管的前端
Start-Process http://127.0.0.1:5000/
