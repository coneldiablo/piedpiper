#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/attack_graph.py

Графовая визуализация атак и поведения малвари.
Использует networkx для построения графов и matplotlib для отрисовки.

Возможности:
- Построение графов процессов, файлов, сети
- Визуализация связей (чтение, запись, соединение)
- Временная шкала событий (timeline)
- Экспорт в различные форматы
- Интерактивные графы для GUI
"""

import json
import logging
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import os

import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.figure import Figure

logger = logging.getLogger("attack_graph")


class AttackGraph:
    """Класс для построения и визуализации графов атак"""

    # Типы узлов
    NODE_PROCESS = "process"
    NODE_FILE = "file"
    NODE_REGISTRY = "registry"
    NODE_NETWORK = "network"
    NODE_MEMORY = "memory"

    # Типы рёбер (операций)
    EDGE_CREATE = "create"
    EDGE_READ = "read"
    EDGE_WRITE = "write"
    EDGE_DELETE = "delete"
    EDGE_EXECUTE = "execute"
    EDGE_CONNECT = "connect"
    EDGE_INJECT = "inject"

    # Цвета для типов узлов
    NODE_COLORS = {
        NODE_PROCESS: "#FF6B6B",      # Красный
        NODE_FILE: "#4ECDC4",         # Бирюзовый
        NODE_REGISTRY: "#FFE66D",     # Жёлтый
        NODE_NETWORK: "#95E1D3",      # Светло-зелёный
        NODE_MEMORY: "#C7CEEA"        # Светло-фиолетовый
    }

    # Цвета для операций
    EDGE_COLORS = {
        EDGE_CREATE: "#2ECC71",       # Зелёный
        EDGE_READ: "#3498DB",         # Синий
        EDGE_WRITE: "#E74C3C",        # Красный
        EDGE_DELETE: "#E67E22",       # Оранжевый
        EDGE_EXECUTE: "#9B59B6",      # Фиолетовый
        EDGE_CONNECT: "#1ABC9C",      # Бирюзовый
        EDGE_INJECT: "#C0392B"        # Тёмно-красный
    }

    def __init__(self):
        self.graph = nx.DiGraph()
        self.timeline = []  # [(timestamp, event_description, nodes_involved)]

    def add_node(self, node_id: str, node_type: str, label: str = None, **attributes):
        """
        Добавить узел в граф

        Args:
            node_id: Уникальный идентификатор узла
            node_type: Тип узла (process/file/registry/network/memory)
            label: Отображаемое имя
            **attributes: Дополнительные атрибуты
        """
        if label is None:
            label = node_id

        self.graph.add_node(
            node_id,
            node_type=node_type,
            label=label,
            **attributes
        )
        logger.debug(f"Добавлен узел: {node_id} ({node_type})")

    def add_edge(self, source: str, target: str, operation: str, timestamp: str = None, **attributes):
        """
        Добавить связь (операцию) между узлами

        Args:
            source: ID исходного узла
            target: ID целевого узла
            operation: Тип операции
            timestamp: Время операции
            **attributes: Дополнительные атрибуты
        """
        self.graph.add_edge(
            source,
            target,
            operation=operation,
            timestamp=timestamp or datetime.now().isoformat(),
            **attributes
        )
        logger.debug(f"Добавлено ребро: {source} --[{operation}]--> {target}")

        # Добавляем в timeline
        if timestamp:
            self.timeline.append((timestamp, operation, source, target))

    def build_from_analysis(self, analysis_data: Dict[str, Any]):
        """
        Построить граф из результатов анализа

        Args:
            analysis_data: Данные статического/динамического анализа
        """
        if not analysis_data:
            return

        # Поддержка старого формата (processes, file_operations и т.д.)
        if "processes" in analysis_data or "file_operations" in analysis_data:
            if "processes" in analysis_data:
                for proc in analysis_data["processes"]:
                    proc_id = f"proc_{proc.get('pid', 'unknown')}"
                    self.add_node(
                        proc_id,
                        self.NODE_PROCESS,
                        label=proc.get("name", "Unknown"),
                        pid=proc.get("pid"),
                        cmdline=proc.get("cmdline"),
                    )

            if "file_operations" in analysis_data:
                for op in analysis_data["file_operations"]:
                    file_id = f"file_{hash(op.get('path', ''))}"
                    proc_id = f"proc_{op.get('pid', 'unknown')}"
                    self.add_node(
                        file_id,
                        self.NODE_FILE,
                        label=os.path.basename(op.get("path", "unknown")),
                        full_path=op.get("path"),
                    )
                    operation = op.get("operation", "unknown")
                    self.add_edge(
                        proc_id,
                        file_id,
                        operation,
                        timestamp=op.get("timestamp"),
                    )

            if "network" in analysis_data:
                for conn in analysis_data["network"]:
                    net_id = f"net_{conn.get('remote_ip', 'unknown')}:{conn.get('remote_port', '0')}"
                    proc_id = f"proc_{conn.get('pid', 'unknown')}"
                    self.add_node(
                        net_id,
                        self.NODE_NETWORK,
                        label=f"{conn.get('remote_ip')}:{conn.get('remote_port')}",
                        protocol=conn.get("protocol"),
                    )
                    self.add_edge(
                        proc_id,
                        net_id,
                        self.EDGE_CONNECT,
                        timestamp=conn.get("timestamp"),
                    )

            if "registry" in analysis_data:
                for reg_op in analysis_data["registry"]:
                    reg_id = f"reg_{hash(reg_op.get('key', ''))}"
                    proc_id = f"proc_{reg_op.get('pid', 'unknown')}"
                    self.add_node(
                        reg_id,
                        self.NODE_REGISTRY,
                        label=reg_op.get("key", "Unknown").split("\\")[-1],
                        full_key=reg_op.get("key"),
                    )
                    operation = reg_op.get("operation", "write")
                    self.add_edge(
                        proc_id,
                        reg_id,
                        operation,
                        timestamp=reg_op.get("timestamp"),
                    )

            if "memory_injections" in analysis_data:
                for inj in analysis_data["memory_injections"]:
                    source_proc = f"proc_{inj.get('source_pid')}"
                    target_proc = f"proc_{inj.get('target_pid')}"
                    self.add_edge(
                        source_proc,
                        target_proc,
                        self.EDGE_INJECT,
                        timestamp=inj.get("timestamp"),
                    )

        # Современный формат dynamic_analysis
        dynamic_section: Optional[Dict[str, Any]] = None
        if "dynamic" in analysis_data:
            dynamic_section = analysis_data.get("dynamic") or {}
        elif any(key in analysis_data for key in ("api_calls", "context", "child_processes")):
            dynamic_section = analysis_data

        if dynamic_section:
            self._build_from_dynamic(dynamic_section)

    def _build_from_dynamic(self, dynamic_data: Dict[str, Any]) -> None:
        """Добавить узлы/рёбра на основе результатов dynamic_analysis."""
        context = dynamic_data.get("context") or {}
        main_pid = context.get("pid") or "main"
        main_node = f"proc_{main_pid}"
        label = context.get("exe")
        if not label:
            cmdline = context.get("cmdline") or []
            label = cmdline[0] if cmdline else "Process"
        self.add_node(main_node, self.NODE_PROCESS, label=os.path.basename(label), pid=context.get("pid"))

        def _label_from_ctx(ctx: Dict[str, Any]) -> str:
            exe = ctx.get("exe")
            if exe:
                return os.path.basename(exe)
            cmd = ctx.get("cmdline") or []
            return os.path.basename(cmd[0]) if cmd else "Process"

        # Child processes
        for pid, child_ctx in (dynamic_data.get("child_processes") or {}).items():
            child_node = f"proc_{pid}"
            self.add_node(child_node, self.NODE_PROCESS, label=_label_from_ctx(child_ctx), pid=child_ctx.get("pid"))
            self.add_edge(main_node, child_node, self.EDGE_CREATE, timestamp=child_ctx.get("create_time"))

        # Helper to add network edges from psutil-like connections
        def add_connections(from_node: str, connections: List[Dict[str, Any]]):
            for conn in connections or []:
                raddr = conn.get("raddr")
                if not raddr:
                    continue
                if isinstance(raddr, (list, tuple)):
                    ip = raddr[0] if len(raddr) > 0 else None
                    port = raddr[1] if len(raddr) > 1 else ""
                elif isinstance(raddr, dict):
                    ip = raddr.get("ip")
                    port = raddr.get("port", "")
                else:
                    ip, port = raddr, ""
                if not ip:
                    continue
                net_id = f"net_{ip}:{port}"
                self.add_node(net_id, self.NODE_NETWORK, label=f"{ip}:{port}")
                self.add_edge(from_node, net_id, self.EDGE_CONNECT, status=conn.get("status"))

        add_connections(main_node, context.get("connections"))
        for pid, child_ctx in (dynamic_data.get("child_processes") or {}).items():
            child_node = f"proc_{pid}"
            add_connections(child_node, child_ctx.get("connections"))

        # Parsed network events list
        for conn in dynamic_data.get("network", []):
            ip = conn.get("remote_ip") or conn.get("ip")
            port = conn.get("remote_port") or conn.get("port", "")
            if not ip:
                continue
            net_id = f"net_{ip}:{port}"
            self.add_node(net_id, self.NODE_NETWORK, label=f"{ip}:{port}", protocol=conn.get("protocol"))
            proc_pid = conn.get("pid") or main_pid
            proc_node = f"proc_{proc_pid}"
            self.add_node(proc_node, self.NODE_PROCESS, label=f"PID {proc_pid}")
            self.add_edge(proc_node, net_id, self.EDGE_CONNECT, timestamp=conn.get("timestamp"))

        # API calls mapped to file/process activity
        for call in dynamic_data.get("api_calls", []):
            api_name = call.get("api") or ""
            pid = call.get("pid") or main_pid
            proc_node = f"proc_{pid}"
            self.add_node(proc_node, self.NODE_PROCESS, label=f"PID {pid}")
            args = call.get("args") or {}

            file_path = args.get("lpFileName") or args.get("filename") or args.get("path")
            if file_path and any(keyword in api_name for keyword in ("CreateFile", "WriteFile", "DeleteFile", "MoveFile")):
                file_id = f"file_{hash(file_path)}"
                self.add_node(file_id, self.NODE_FILE, label=os.path.basename(file_path), full_path=file_path)
                operation = self.EDGE_WRITE if "Write" in api_name else self.EDGE_DELETE if "Delete" in api_name else self.EDGE_CREATE
                self.add_edge(proc_node, file_id, operation, timestamp=call.get("timestamp"))

            if api_name in ("CreateProcessW", "CreateProcessA", "NtCreateProcess", "NtCreateProcessEx"):
                cmd = args.get("commandLine") or args.get("applicationName")
                if cmd:
                    created_id = f"proc_{hash(cmd)}"
                    self.add_node(created_id, self.NODE_PROCESS, label=str(cmd))
                    self.add_edge(proc_node, created_id, self.EDGE_CREATE, timestamp=call.get("timestamp"))

    def visualize(self, output_path: str = None, layout: str = "spring", figsize: Tuple[int, int] = (16, 12)) -> Figure:
        """
        Визуализировать граф

        Args:
            output_path: Путь для сохранения изображения
            layout: Тип layout (spring/circular/kamada_kawai/shell)
            figsize: Размер фигуры

        Returns:
            matplotlib Figure
        """
        if self.graph.number_of_nodes() == 0:
            logger.warning("Граф пуст, нечего визуализировать")
            return None

        fig, ax = plt.subplots(figsize=figsize)
        fig.patch.set_facecolor('#1E1E1E')  # Тёмный фон
        ax.set_facecolor('#2D2D2D')

        # Выбираем layout
        if layout == "spring":
            pos = nx.spring_layout(self.graph, k=2, iterations=50)
        elif layout == "circular":
            pos = nx.circular_layout(self.graph)
        elif layout == "kamada_kawai":
            pos = nx.kamada_kawai_layout(self.graph)
        elif layout == "shell":
            pos = nx.shell_layout(self.graph)
        else:
            pos = nx.spring_layout(self.graph)

        # Получаем цвета узлов
        node_colors = [
            self.NODE_COLORS.get(self.graph.nodes[node].get("node_type"), "#CCCCCC")
            for node in self.graph.nodes()
        ]

        # Рисуем узлы
        nx.draw_networkx_nodes(
            self.graph,
            pos,
            node_color=node_colors,
            node_size=3000,
            alpha=0.9,
            ax=ax
        )

        # Получаем метки узлов
        labels = {
            node: self.graph.nodes[node].get("label", node)
            for node in self.graph.nodes()
        }

        # Рисуем метки
        nx.draw_networkx_labels(
            self.graph,
            pos,
            labels,
            font_size=9,
            font_color="white",
            font_weight="bold",
            ax=ax
        )

        # Рисуем рёбра по операциям
        for operation, color in self.EDGE_COLORS.items():
            edge_list = [
                (u, v) for u, v, d in self.graph.edges(data=True)
                if d.get("operation") == operation
            ]
            if edge_list:
                nx.draw_networkx_edges(
                    self.graph,
                    pos,
                    edgelist=edge_list,
                    edge_color=color,
                    arrows=True,
                    arrowsize=20,
                    arrowstyle="->",
                    width=2,
                    alpha=0.7,
                    ax=ax
                )

        # Создаём легенду
        node_patches = [
            mpatches.Patch(color=color, label=ntype.capitalize())
            for ntype, color in self.NODE_COLORS.items()
        ]
        edge_patches = [
            mpatches.Patch(color=color, label=op.capitalize())
            for op, color in self.EDGE_COLORS.items()
        ]

        legend1 = ax.legend(handles=node_patches, loc='upper left', title="Node Types", fontsize=10)
        legend1.get_frame().set_facecolor('#2D2D2D')
        legend1.get_frame().set_edgecolor('white')
        for text in legend1.get_texts():
            text.set_color("white")
        legend1.get_title().set_color("white")

        ax.add_artist(legend1)

        legend2 = ax.legend(handles=edge_patches, loc='upper right', title="Operations", fontsize=10)
        legend2.get_frame().set_facecolor('#2D2D2D')
        legend2.get_frame().set_edgecolor('white')
        for text in legend2.get_texts():
            text.set_color("white")
        legend2.get_title().set_color("white")

        ax.set_title("Attack Behavior Graph", color="white", fontsize=18, fontweight="bold", pad=20)
        ax.axis("off")

        plt.tight_layout()

        if output_path:
            plt.savefig(output_path, dpi=300, facecolor='#1E1E1E', edgecolor='none')
            logger.info(f"Граф сохранён: {output_path}")

        return fig

    def visualize_on_ax(self, ax, layout: str = "spring") -> None:
        """Render the graph on an existing matplotlib axis."""
        if self.graph.number_of_nodes() == 0:
            logger.warning("Graph is empty; nothing to render")
            ax.clear()
            ax.set_axis_off()
            return

        fig = ax.figure
        fig.patch.set_facecolor('#1E1E1E')
        ax.set_facecolor('#2D2D2D')
        ax.clear()

        if layout == "spring":
            pos = nx.spring_layout(self.graph, k=2, iterations=50)
        elif layout == "circular":
            pos = nx.circular_layout(self.graph)
        elif layout == "kamada_kawai":
            pos = nx.kamada_kawai_layout(self.graph)
        elif layout == "shell":
            pos = nx.shell_layout(self.graph)
        else:
            pos = nx.spring_layout(self.graph)

        node_colors = [
            self.NODE_COLORS.get(self.graph.nodes[node].get("node_type"), "#CCCCCC")
            for node in self.graph.nodes()
        ]

        nx.draw_networkx_nodes(
            self.graph,
            pos,
            node_color=node_colors,
            node_size=3000,
            alpha=0.9,
            ax=ax
        )

        labels = {
            node: self.graph.nodes[node].get("label", node)
            for node in self.graph.nodes()
        }

        nx.draw_networkx_labels(
            self.graph,
            pos,
            labels,
            font_size=9,
            font_color="white",
            font_weight="bold",
            ax=ax
        )

        for operation, color in self.EDGE_COLORS.items():
            edge_list = [
                (u, v) for u, v, d in self.graph.edges(data=True)
                if d.get("operation") == operation
            ]
            if edge_list:
                nx.draw_networkx_edges(
                    self.graph,
                    pos,
                    edgelist=edge_list,
                    edge_color=color,
                    arrows=True,
                    arrowsize=20,
                    arrowstyle="->",
                    width=2,
                    alpha=0.7,
                    ax=ax
                )

        node_patches = [
            mpatches.Patch(color=color, label=ntype.capitalize())
            for ntype, color in self.NODE_COLORS.items()
        ]
        edge_patches = [
            mpatches.Patch(color=color, label=op.capitalize())
            for op, color in self.EDGE_COLORS.items()
        ]

        legend1 = ax.legend(handles=node_patches, loc='upper left', title="Node Types", fontsize=10)
        legend1.get_frame().set_facecolor('#2D2D2D')
        legend1.get_frame().set_edgecolor('white')
        for text in legend1.get_texts():
            text.set_color("white")
        legend1.get_title().set_color("white")

        ax.add_artist(legend1)

        legend2 = ax.legend(handles=edge_patches, loc='upper right', title="Operations", fontsize=10)
        legend2.get_frame().set_facecolor('#2D2D2D')
        legend2.get_frame().set_edgecolor('white')
        for text in legend2.get_texts():
            text.set_color("white")
        legend2.get_title().set_color("white")

        ax.set_title("Attack Behavior Graph", color="white", fontsize=18, fontweight="bold", pad=20)
        ax.axis("off")
        fig.tight_layout()

    def generate_timeline(self, output_path: str = None) -> Figure:
        """
        Генерация временной шкалы событий

        Args:
            output_path: Путь для сохранения

        Returns:
            matplotlib Figure
        """
        if not self.timeline:
            logger.warning("Timeline пуст")
            return None

        # Сортируем события по времени
        sorted_timeline = sorted(self.timeline, key=lambda x: x[0])

        fig, ax = plt.subplots(figsize=(14, 8))
        fig.patch.set_facecolor('#1E1E1E')
        ax.set_facecolor('#2D2D2D')

        # Группируем по операциям
        operations = {}
        for i, (timestamp, operation, source, target) in enumerate(sorted_timeline):
            if operation not in operations:
                operations[operation] = []
            operations[operation].append((i, f"{source} → {target}"))

        # Рисуем timeline
        y_pos = 0
        colors = list(self.EDGE_COLORS.values())

        for idx, (operation, events) in enumerate(operations.items()):
            color = self.EDGE_COLORS.get(operation, "#CCCCCC")
            for event_idx, label in events:
                ax.barh(y_pos, 1, left=event_idx, height=0.8, color=color, alpha=0.8)
                ax.text(event_idx + 0.5, y_pos, label, va='center', ha='center', fontsize=8, color='white')
                y_pos += 1

        ax.set_xlabel("Event Sequence", color="white", fontsize=12)
        ax.set_ylabel("Events", color="white", fontsize=12)
        ax.set_title("Attack Timeline", color="white", fontsize=16, fontweight="bold")
        ax.tick_params(colors='white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        plt.tight_layout()

        if output_path:
            plt.savefig(output_path, dpi=300, facecolor='#1E1E1E')
            logger.info(f"Timeline сохранён: {output_path}")

        return fig

    def export_to_json(self, output_path: str):
        """Экспорт графа в JSON"""
        data = nx.node_link_data(self.graph)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Граф экспортирован в JSON: {output_path}")

    def export_to_graphml(self, output_path: str):
        """Экспорт графа в GraphML (для Gephi и т.д.)"""
        nx.write_graphml(self.graph, output_path)
        logger.info(f"Граф экспортирован в GraphML: {output_path}")

    def get_statistics(self) -> Dict[str, Any]:
        """Получить статистику графа"""
        stats = {
            "nodes_count": self.graph.number_of_nodes(),
            "edges_count": self.graph.number_of_edges(),
            "node_types": {},
            "operations": {},
            "most_active_nodes": []
        }

        # Считаем типы узлов
        for node, data in self.graph.nodes(data=True):
            ntype = data.get("node_type", "unknown")
            stats["node_types"][ntype] = stats["node_types"].get(ntype, 0) + 1

        # Считаем операции
        for u, v, data in self.graph.edges(data=True):
            op = data.get("operation", "unknown")
            stats["operations"][op] = stats["operations"].get(op, 0) + 1

        # Находим самые активные узлы (по степени)
        degrees = dict(self.graph.degree())
        sorted_nodes = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:5]
        stats["most_active_nodes"] = [
            {
                "id": node,
                "label": self.graph.nodes[node].get("label", node),
                "connections": degree
            }
            for node, degree in sorted_nodes
        ]

        return stats


def create_attack_graph_from_analysis(analysis_data: Dict[str, Any]) -> AttackGraph:
    """
    Быстрая функция для создания графа из анализа

    Args:
        analysis_data: Результаты динамического анализа

    Returns:
        AttackGraph объект
    """
    graph = AttackGraph()
    graph.build_from_analysis(analysis_data)
    return graph


if __name__ == "__main__":
    # Тестирование модуля
    logging.basicConfig(level=logging.INFO)

    # Тестовые данные
    test_data = {
        "processes": [
            {"pid": 1234, "name": "malware.exe", "cmdline": "C:\\malware.exe"},
            {"pid": 5678, "name": "cmd.exe", "cmdline": "cmd.exe /c whoami"}
        ],
        "file_operations": [
            {"pid": 1234, "path": "C:\\Windows\\System32\\config.dat", "operation": "write", "timestamp": "2025-01-01T10:00:00"},
            {"pid": 1234, "path": "C:\\Users\\victim\\data.txt", "operation": "read", "timestamp": "2025-01-01T10:00:05"}
        ],
        "network": [
            {"pid": 1234, "remote_ip": "192.168.1.100", "remote_port": 4444, "protocol": "TCP", "timestamp": "2025-01-01T10:00:10"}
        ],
        "registry": [
            {"pid": 1234, "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "operation": "write", "timestamp": "2025-01-01T10:00:15"}
        ]
    }

    print("=== Создание графа атак ===")
    graph = create_attack_graph_from_analysis(test_data)

    print("\n=== Статистика ===")
    stats = graph.get_statistics()
    print(json.dumps(stats, indent=2, ensure_ascii=False))

    print("\n=== Визуализация ===")
    graph.visualize("test_attack_graph.png", layout="spring")
    print("График сохранён: test_attack_graph.png")

    print("\n=== Timeline ===")
    graph.generate_timeline("test_timeline.png")
    print("Timeline сохранён: test_timeline.png")
