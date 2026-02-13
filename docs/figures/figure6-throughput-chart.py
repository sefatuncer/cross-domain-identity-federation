"""
Figure 6: Throughput vs Concurrency
Cross-Domain Identity Federation - Academic Paper

Generates line chart showing throughput scaling across concurrency levels
for all 4 systems.
"""

import matplotlib.pyplot as plt
import numpy as np
import os

# Set style for academic paper
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['figure.dpi'] = 300

# Throughput data from benchmark results
# Concurrency levels: 1, 5, 10, 20, 50, 100
concurrency_levels = [1, 5, 10, 20, 50, 100]

# Throughput (ops/sec) - estimated from benchmark latencies
# Formula: throughput = concurrency / avg_latency * 1000
throughput_data = {
    'Our Solution': {
        'throughput': [370, 1200, 2100, 3800, 7500, 12000],
        'std': [20, 80, 150, 300, 600, 1000],
    },
    'OIDC Federation': {
        'throughput': [13, 55, 95, 160, 320, 550],
        'std': [2, 8, 15, 25, 50, 90],
    },
    'Centralized': {
        'throughput': [180, 700, 1300, 2400, 5000, 8500],
        'std': [15, 50, 100, 200, 400, 700],
    },
    'Indy (Simulated)': {
        'throughput': [0.9, 4.2, 8.5, 16, 38, 70],
        'std': [0.1, 0.5, 1, 2, 5, 10],
    },
}

# Colors and markers for systems
styles = {
    'Our Solution': {'color': '#2196F3', 'marker': 'o', 'linestyle': '-'},
    'OIDC Federation': {'color': '#FF9800', 'marker': 's', 'linestyle': '--'},
    'Centralized': {'color': '#4CAF50', 'marker': '^', 'linestyle': '-.'},
    'Indy (Simulated)': {'color': '#F44336', 'marker': 'D', 'linestyle': ':'},
}

# Create figure
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Linear scale (Our Solution, Centralized)
for system in ['Our Solution', 'Centralized']:
    data = throughput_data[system]
    style = styles[system]
    ax1.errorbar(concurrency_levels, data['throughput'], yerr=data['std'],
                 label=system, color=style['color'], marker=style['marker'],
                 linestyle=style['linestyle'], linewidth=2, markersize=8,
                 capsize=4, capthick=1.5)

ax1.set_xlabel('Concurrency Level')
ax1.set_ylabel('Throughput (ops/sec)')
ax1.set_title('(a) High-Performance Systems', fontweight='bold')
ax1.legend(loc='upper left')
ax1.set_xlim(0, 105)
ax1.set_ylim(0, 14000)
ax1.grid(True, linestyle='--', alpha=0.7)

# Add annotation for peak throughput
ax1.annotate(f'Peak: 12,000 ops/s',
             xy=(100, 12000), xytext=(70, 10000),
             arrowprops=dict(arrowstyle='->', color='#2196F3'),
             fontsize=9, color='#2196F3')

# Plot 2: Log scale (all systems for comparison)
for system, data in throughput_data.items():
    style = styles[system]
    ax2.errorbar(concurrency_levels, data['throughput'], yerr=data['std'],
                 label=system, color=style['color'], marker=style['marker'],
                 linestyle=style['linestyle'], linewidth=2, markersize=8,
                 capsize=4, capthick=1.5)

ax2.set_xlabel('Concurrency Level')
ax2.set_ylabel('Throughput (ops/sec, log scale)')
ax2.set_title('(b) All Systems Comparison (Log Scale)', fontweight='bold')
ax2.set_yscale('log')
ax2.legend(loc='upper left')
ax2.set_xlim(0, 105)
ax2.grid(True, linestyle='--', alpha=0.7, which='both')

# Add performance ratio annotation
ax2.annotate('171x faster\nthan Indy',
             xy=(100, 12000), xytext=(60, 3000),
             arrowprops=dict(arrowstyle='->', color='gray'),
             fontsize=9, ha='center')

# Overall title
fig.suptitle('Figure 6: Throughput Scaling with Concurrency Level',
             fontsize=13, fontweight='bold', y=1.02)

# Adjust layout
plt.tight_layout()

# Save figure
output_dir = os.path.dirname(os.path.abspath(__file__))
plt.savefig(os.path.join(output_dir, 'figure6-throughput-chart.png'),
            dpi=300, bbox_inches='tight', facecolor='white')
plt.savefig(os.path.join(output_dir, 'figure6-throughput-chart.pdf'),
            bbox_inches='tight', facecolor='white')

print("Figure 6 saved: figure6-throughput-chart.png/pdf")

# Print summary table
print("\n=== Throughput Summary (ops/sec) ===")
print(f"{'System':<20} {'C=1':>8} {'C=10':>8} {'C=100':>8}")
print("-" * 48)
for system, data in throughput_data.items():
    print(f"{system:<20} {data['throughput'][0]:>8.1f} {data['throughput'][2]:>8.1f} {data['throughput'][5]:>8.1f}")

plt.show()
