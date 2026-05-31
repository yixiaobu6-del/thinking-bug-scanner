"""
思维漏洞扫描器 - 综合检查器
整合逻辑谬误和认知偏误检测
"""

import json
from typing import Optional

from .fallacies import FallacyDetector
from .biases import BiasDetector


class ThinkingChecker:
    """思维漏洞综合检查器"""

    def __init__(self):
        """初始化检测器"""
        self.fallacy_detector = FallacyDetector()
        self.bias_detector = BiasDetector()

    def scan(self, text: str) -> list:
        """
        对文本进行综合扫描

        Args:
            text: 待检测文本

        Returns:
            所有检测到的问题列表
        """
        if not text or not text.strip():
            return []

        # 分段处理，每段独立检测
        paragraphs = [p.strip() for p in text.split('\n') if p.strip()]

        all_results = []

        for para in paragraphs:
            if len(para) < 5:  # 过短的段落跳过
                continue

            # 检测逻辑谬误
            fallacy_results = self.fallacy_detector.detect(para)
            for r in fallacy_results:
                all_results.append(r)

            # 检测认知偏误
            bias_results = self.bias_detector.detect(para)
            for r in bias_results:
                all_results.append(r)

        # 全局排序
        all_results.sort(key=lambda x: x['position'])

        return all_results

    def generate_summary(self, results: list) -> dict:
        """
        生成扫描结果摘要

        Args:
            results: 扫描结果列表

        Returns:
            摘要信息
        """
        if not results:
            return {
                'total_issues': 0,
                'total_fallacies': 0,
                'total_biases': 0,
                'severity_counts': {'high': 0, 'medium': 0, 'low': 0},
                'score': 100,
                'evaluation': '未检测到逻辑问题'
            }

        # 统计各类问题数量
        fallacies = [r for r in results if r['type'] == 'fallacy']
        biases = [r for r in results if r['type'] == 'bias']

        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for r in results:
            severity_counts[r['severity']] = severity_counts.get(r['severity'], 0) + 1

        # 计算思维质量分数（扣分制）
        score = 100
        score -= len(fallacies) * 5  # 每个谬误扣5分
        score -= len(biases) * 3     # 每个偏误扣3分
        score -= severity_counts.get('high', 0) * 5  # 严重问题额外扣分
        score = max(0, min(100, score))

        # 评价等级
        if score >= 90:
            evaluation = '思维质量优秀，逻辑较为严密'
        elif score >= 70:
            evaluation = '思维质量良好，存在少量可改进之处'
        elif score >= 50:
            evaluation = '思维质量一般，建议仔细检查问题和改进'
        else:
            evaluation = '思维漏洞较多，建议系统性地进行批判性思维训练'

        return {
            'total_issues': len(results),
            'total_fallacies': len(fallacies),
            'total_biases': len(biases),
            'fallacy_types': {r['name'] for r in fallacies},
            'bias_types': {r['name'] for r in biases},
            'severity_counts': severity_counts,
            'score': score,
            'evaluation': evaluation
        }

    def format_report(self, text: str, results: list) -> str:
        """
        生成可读的扫描报告

        Args:
            text: 原始文本
            results: 扫描结果

        Returns:
            格式化的报告文本
        """
        summary = self.generate_summary(results)

        report = []
        report.append("=" * 50)
        report.append("思维漏洞扫描报告")
        report.append("=" * 50)
        report.append(f"")
        report.append(f"评分: {summary['score']}/100")
        report.append(f"评价: {summary['evaluation']}")
        report.append(f"")
        report.append(f"问题总数: {summary['total_issues']}")
        report.append(f"  逻辑谬误: {summary['total_fallacies']}")
        report.append(f"  认知偏误: {summary['total_biases']}")
        report.append(f"  严重问题: {summary['severity_counts']['high']}")
        report.append(f"  中等问题: {summary['severity_counts']['medium']}")
        report.append(f"  轻微问题: {summary['severity_counts']['low']}")
        report.append(f"")

        if results:
            report.append("-" * 50)
            report.append("详细问题列表")
            report.append("-" * 50)

            for i, result in enumerate(results, 1):
                label = "逻辑谬误" if result['type'] == 'fallacy' else "认知偏误"
                severity_icon = "严重" if result['severity'] == 'high' else ("中等" if result['severity'] == 'medium' else "轻微")

                report.append(f"")
                report.append(f"#{i} [{label}] [{severity_icon}] {result['name']}")
                report.append(f"   说明: {result['description']}")
                report.append(f"   匹配内容: \"{result['matched']}\"")
                report.append(f"   改进建议: {result['suggestion']}")

        report.append(f"")
        report.append("=" * 50)

        return '\n'.join(report)


if __name__ == '__main__':
    checker = ThinkingChecker()

    test_text = """
    我认为这个方案很好，因为所有竞争对手都在这么做。
    你这个连基本常识都不懂的人，有什么资格评价我的方案？
    要么接受我的方案，要么就是不想让公司发展。
    如果采用这个新技术，公司就会陷入混乱，最终倒闭。
    我早就知道这个项目会失败，当初就觉得不对劲。
    """

    results = checker.scan(test_text)
    report = checker.format_report(test_text, results)
    print(report)