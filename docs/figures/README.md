# Figure Source Files

Bu klasör makale için gerekli figürlerin kaynak kodlarını içerir.

## Figür Listesi

| Figure | Dosya | Format | Durum |
|--------|-------|--------|-------|
| Figure 1 | system-architecture.puml | PlantUML | ✓ |
| Figure 2 | fabric-network.puml | PlantUML | ✓ |
| Figure 3 | cross-domain-flow.puml | PlantUML | ✓ |
| Figure 4 | sequence-diagram.puml | PlantUML | ✓ |
| Figure 5 | latency-boxplot.py | Python/Matplotlib | ✓ |
| Figure 6 | throughput-chart.py | Python/Matplotlib | ✓ |

## Render Etme

### PlantUML Figürleri
```bash
# PlantUML ile render
java -jar plantuml.jar *.puml

# Veya online: https://www.plantuml.com/plantuml/
```

### Python Figürleri
```bash
pip install matplotlib pandas seaborn
python latency-boxplot.py
python throughput-chart.py
```
