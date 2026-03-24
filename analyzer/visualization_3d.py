#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/visualization_3d.py

3D визуализация атак и поведения малвари.
Использует mpl_toolkits.mplot3d для построения 3D графов.

Возможности:
- 3D граф процессов и связей
- Анимация атак в реальном времени
- Временная ось (Z-координата как время)
- Интерактивная визуализация
"""

import logging
from typing import Dict, List, Any, Tuple, Optional
import numpy as np
from datetime import datetime

import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from mpl_toolkits.mplot3d.art3d import Line3DCollection
from matplotlib.animation import FuncAnimation
from matplotlib.figure import Figure
import networkx as nx

logger = logging.getLogger("visualization_3d")


class AttackVisualization3D:
    """Класс для 3D визуализации атак"""

    def __init__(self):
        self.events = []  # [(timestamp, source, target, operation, attributes)]
        self.nodes = {}   # {node_id: (x, y, z, type)}

    def add_event(self, timestamp: float, source: str, target: str, operation: str, **attributes):
        """
        Добавить событие

        Args:
            timestamp: Временная метка (Unix time или индекс)
            source: Исходный узел
            target: Целевой узел
            operation: Тип операции
            **attributes: Дополнительные атрибуты
        """
        self.events.append({
            "timestamp": timestamp,
            "source": source,
            "target": target,
            "operation": operation,
            **attributes
        })

    def build_from_timeline(self, timeline_data: List[Dict[str, Any]]):
        """
        Построить 3D визуализацию из timeline

        Args:
            timeline_data: Список событий с временными метками
        """
        for event in timeline_data:
            timestamp = event.get("timestamp", 0)
            if isinstance(timestamp, str):
                # Конвертируем ISO timestamp в float
                try:
                    dt = datetime.fromisoformat(timestamp)
                    timestamp = dt.timestamp()
                except:
                    timestamp = len(self.events)

            self.add_event(
                timestamp=timestamp,
                source=event.get("source", "unknown"),
                target=event.get("target", "unknown"),
                operation=event.get("operation", "unknown"),
                **{k: v for k, v in event.items() if k not in ["timestamp", "source", "target", "operation"]}
            )

    def visualize_3d(self, output_path: str = None, figsize: Tuple[int, int] = (16, 12), ax: Optional[Axes3D] = None) -> Figure:
        """
        Создать 3D визуализацию

        Args:
            output_path: Путь для сохранения
            figsize: Размер фигуры

        Returns:
            matplotlib Figure
        """
        if not self.events:
            logger.warning("Нет событий для визуализации")
            return None

        created_figure = False
        if ax is None:
            fig = plt.figure(figsize=figsize)
            created_figure = True
            ax = fig.add_subplot(111, projection='3d')
        else:
            fig = ax.figure
            fig.set_size_inches(*figsize)
            ax.clear()
        fig.patch.set_facecolor('#1E1E1E')
        ax.set_facecolor('#2D2D2D')

        # Извлекаем уникальные узлы
        nodes = set()
        for event in self.events:
            nodes.add(event["source"])
            nodes.add(event["target"])

        # Присваиваем координаты узлам (круговое размещение в XY)
        node_positions = {}
        n = len(nodes)
        for idx, node in enumerate(sorted(nodes)):
            angle = 2 * np.pi * idx / n
            x = np.cos(angle) * 5
            y = np.sin(angle) * 5
            node_positions[node] = (x, y)

        # Нормализуем временные метки для Z координаты
        timestamps = [e["timestamp"] for e in self.events]
        min_time = min(timestamps)
        max_time = max(timestamps)
        time_range = max_time - min_time if max_time > min_time else 1

        # Цвета операций
        operation_colors = {
            "create": "#2ECC71",
            "read": "#3498DB",
            "write": "#E74C3C",
            "delete": "#E67E22",
            "execute": "#9B59B6",
            "connect": "#1ABC9C",
            "inject": "#C0392B"
        }

        # Рисуем связи как 3D линии
        for event in self.events:
            source = event["source"]
            target = event["target"]
            timestamp = event["timestamp"]
            operation = event["operation"]

            # Получаем координаты
            x1, y1 = node_positions.get(source, (0, 0))
            x2, y2 = node_positions.get(target, (0, 0))
            z = ((timestamp - min_time) / time_range) * 10  # Масштабируем время

            # Рисуем линию
            color = operation_colors.get(operation, "#CCCCCC")
            ax.plot(
                [x1, x2],
                [y1, y2],
                [z, z],
                color=color,
                alpha=0.6,
                linewidth=2
            )

        # Рисуем узлы на разных временных слоях
        for node, (x, y) in node_positions.items():
            # Узел появляется в разное время
            node_events = [e for e in self.events if e["source"] == node or e["target"] == node]
            if node_events:
                first_time = min(e["timestamp"] for e in node_events)
                z = ((first_time - min_time) / time_range) * 10

                ax.scatter(
                    [x], [y], [z],
                    s=500,
                    c='#FF6B6B',
                    alpha=0.9,
                    edgecolors='white',
                    linewidth=2
                )

                # Подпись узла
                ax.text(x, y, z, node, fontsize=8, color='white', ha='center', va='bottom')

        # Настройки осей
        ax.set_xlabel('X (Spatial)', color='white', fontsize=10)
        ax.set_ylabel('Y (Spatial)', color='white', fontsize=10)
        ax.set_zlabel('Z (Time →)', color='white', fontsize=10)
        ax.set_title('3D Attack Timeline Visualization', color='white', fontsize=16, fontweight='bold', pad=20)

        # Цвет осей и сетки
        ax.xaxis.pane.set_facecolor('#2D2D2D')
        ax.yaxis.pane.set_facecolor('#2D2D2D')
        ax.zaxis.pane.set_facecolor('#2D2D2D')
        ax.tick_params(colors='white')
        ax.xaxis.label.set_color('white')
        ax.yaxis.label.set_color('white')
        ax.zaxis.label.set_color('white')

        # Легенда операций
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor=color, label=op.capitalize())
            for op, color in operation_colors.items()
        ]
        legend = ax.legend(handles=legend_elements, loc='upper left', fontsize=9, framealpha=0.9)
        legend.get_frame().set_facecolor('#2D2D2D')
        legend.get_frame().set_edgecolor('white')
        for text in legend.get_texts():
            text.set_color("white")

        plt.tight_layout()

        if output_path:
            plt.savefig(output_path, dpi=300, facecolor='#1E1E1E')
            logger.info(f"3D визуализация сохранена: {output_path}")

        return fig

    def create_animated_attack(self, output_path: str = None, fps: int = 10, duration: int = 10):
        """
        Создать анимацию атаки в реальном времени

        Args:
            output_path: Путь для сохранения (MP4 или GIF)
            fps: Кадров в секунду
            duration: Длительность в секундах
        """
        if not self.events:
            logger.warning("Нет событий для анимации")
            return

        fig = plt.figure(figsize=(14, 10))
        fig.patch.set_facecolor('#1E1E1E')
        ax = fig.add_subplot(111, projection='3d')
        ax.set_facecolor('#2D2D2D')

        # Подготовка данных
        nodes = set()
        for event in self.events:
            nodes.add(event["source"])
            nodes.add(event["target"])

        node_positions = {}
        n = len(nodes)
        for idx, node in enumerate(sorted(nodes)):
            angle = 2 * np.pi * idx / n
            x = np.cos(angle) * 5
            y = np.sin(angle) * 5
            node_positions[node] = (x, y)

        timestamps = [e["timestamp"] for e in self.events]
        min_time = min(timestamps)
        max_time = max(timestamps)
        time_range = max_time - min_time if max_time > min_time else 1

        lines_collection = []
        scatter_points = []

        def init():
            ax.set_xlabel('X', color='white')
            ax.set_ylabel('Y', color='white')
            ax.set_zlabel('Time →', color='white')
            ax.set_title('Real-time Attack Animation', color='white', fontsize=14)
            ax.set_xlim(-6, 6)
            ax.set_ylim(-6, 6)
            ax.set_zlim(0, 10)
            return []

        def update(frame):
            ax.clear()
            init()

            # Показываем события до текущего кадра
            current_frame = frame % len(self.events)
            visible_events = self.events[:current_frame + 1]

            for event in visible_events:
                source = event["source"]
                target = event["target"]
                timestamp = event["timestamp"]

                x1, y1 = node_positions.get(source, (0, 0))
                x2, y2 = node_positions.get(target, (0, 0))
                z = ((timestamp - min_time) / time_range) * 10

                ax.plot(
                    [x1, x2],
                    [y1, y2],
                    [z, z],
                    color='#E74C3C',
                    alpha=0.7,
                    linewidth=2
                )

            # Рисуем узлы
            for node, (x, y) in node_positions.items():
                ax.scatter([x], [y], [0], s=400, c='#FF6B6B', alpha=0.9, edgecolors='white', linewidth=2)
                ax.text(x, y, 0, node, fontsize=7, color='white', ha='center')

            return []

        frames = min(len(self.events), fps * duration)
        anim = FuncAnimation(fig, update, frames=frames, init_func=init, interval=1000 // fps, blit=False)

        if output_path:
            try:
                if output_path.endswith('.gif'):
                    anim.save(output_path, writer='pillow', fps=fps)
                else:
                    anim.save(output_path, writer='ffmpeg', fps=fps)
                logger.info(f"Анимация сохранена: {output_path}")
            except Exception as e:
                logger.error(f"Ошибка сохранения анимации: {e}")
        else:
            if created_figure:
                plt.show()

        return anim


def create_3d_visualization_from_data(data: Dict[str, Any], output_path: str = None) -> Figure:
    """
    Быстрая функция для создания 3D визуализации

    Args:
        data: Данные анализа с временными метками
        output_path: Путь сохранения

    Returns:
        matplotlib Figure
    """
    viz = AttackVisualization3D()

    # Парсим события из разных источников
    all_events = []

    if "file_operations" in data:
        for op in data["file_operations"]:
            all_events.append({
                "timestamp": op.get("timestamp", ""),
                "source": f"proc_{op.get('pid', 'unknown')}",
                "target": f"file_{hash(op.get('path', ''))}",
                "operation": op.get("operation", "unknown")
            })

    if "network" in data:
        for conn in data["network"]:
            all_events.append({
                "timestamp": conn.get("timestamp", ""),
                "source": f"proc_{conn.get('pid', 'unknown')}",
                "target": f"net_{conn.get('remote_ip', 'unknown')}",
                "operation": "connect"
            })

    if "registry" in data:
        for reg_op in data["registry"]:
            all_events.append({
                "timestamp": reg_op.get("timestamp", ""),
                "source": f"proc_{reg_op.get('pid', 'unknown')}",
                "target": f"reg_{hash(reg_op.get('key', ''))}",
                "operation": reg_op.get("operation", "write")
            })

    viz.build_from_timeline(all_events)
    return viz.visualize_3d(output_path=output_path)


if __name__ == "__main__":
    # Тестирование
    logging.basicConfig(level=logging.INFO)

    test_data = {
        "file_operations": [
            {"pid": 1234, "path": "/tmp/test1.txt", "operation": "write", "timestamp": "2025-01-01T10:00:00"},
            {"pid": 1234, "path": "/tmp/test2.txt", "operation": "read", "timestamp": "2025-01-01T10:00:05"},
            {"pid": 5678, "path": "/tmp/test3.txt", "operation": "write", "timestamp": "2025-01-01T10:00:10"}
        ],
        "network": [
            {"pid": 1234, "remote_ip": "192.168.1.100", "protocol": "TCP", "timestamp": "2025-01-01T10:00:15"}
        ]
    }

    print("=== Создание 3D визуализации ===")
    fig = create_3d_visualization_from_data(test_data, "test_3d_attack.png")
    print("3D визуализация сохранена: test_3d_attack.png")
