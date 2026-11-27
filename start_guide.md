# 在项目根目录 D:\AgentDojo\agentdojo 下执行
conda activate agent
python -m agentdojo.method.visualization.server

# 另外开一个 PowerShell 终端，在项目根目录打开前端
Start-Process .\frontend\index.html
