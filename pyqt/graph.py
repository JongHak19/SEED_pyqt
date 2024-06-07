import matplotlib.pyplot as plt
from matplotlib import rc
import numpy as np

rc('font', family='AppleGothic') 			## mac용
plt.rcParams['axes.unicode_minus'] = False  
# 데이터 생성
modes = ["CBC", "CCM", "CTR", "ECB", "GCM"]
execution_time = [0.1244892120361328, 0.0922250747680664, 0.06734275817871094, 0.08922386169433594, 0.07772183418273926]
cpu_usage = [4.5, 9.6, 4.8, 6.4, 7.0]
memory_usage = [81920, 16384, 0, 0, 0]

x = np.arange(len(modes))

# 그래프 그리기
fig, ax1 = plt.subplots()

color = 'tab:blue'
ax1.set_xlabel('모드')
ax1.set_ylabel('실행 시간 (seconds)', color=color)
ax1.bar(x - 0.2, execution_time, 0.4, label='실행 시간', color=color)
ax1.tick_params(axis='y', labelcolor=color)

ax2 = ax1.twinx()
color = 'tab:orange'
ax2.set_ylabel('CPU 사용률 (%)', color=color)
ax2.plot(x, cpu_usage, label='CPU 사용률', color=color, marker='o')
ax2.tick_params(axis='y', labelcolor=color)

fig.tight_layout()
fig.legend(loc="upper left", bbox_to_anchor=(0.1,0.9))

plt.title('SEED 알고리즘의 모드별 성능 비교')
fig.subplots_adjust(top=0.85)  # 상단 여백을 조절합니다
plt.xticks(x, modes)
plt.show()

# 메모리 사용량 그래프
plt.figure(figsize=(10, 6))
plt.bar(modes, memory_usage, color='tab:green')
plt.xlabel('모드')
plt.ylabel('메모리 사용량 (Bytes)')
plt.title('SEED 알고리즘의 모드별 메모리 사용량 비교')
plt.show()
