"""
思维漏洞扫描器 - Web应用
基于Flask的思维漏洞检测Web服务
"""

import json
import re
import sys
from pathlib import Path

from flask import Flask, render_template, request, jsonify

# 添加当前目录到搜索路径
sys.path.insert(0, str(Path(__file__).parent))

from scanner.checker import ThinkingChecker

app = Flask(__name__)
checker = ThinkingChecker()


@app.route('/')
def index():
    """首页"""
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    """执行思维漏洞扫描"""
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({'error': '请输入需要扫描的文本'}), 400

    text = data['text'].strip()
    if not text:
        return jsonify({'error': '文本不能为空'}), 400

    try:
        results = checker.scan(text)
        return jsonify({
            'text': text,
            'result_count': len(results),
            'results': results,
            'summary': checker.generate_summary(results)
        })
    except Exception as e:
        return jsonify({'error': f'扫描出错：{str(e)}'}), 500


@app.route('/checklist', methods=['GET'])
def checklist():
    """获取支持的检测类型列表"""
    fallacies = [
        {'name': '人身攻击谬误', 'description': '攻击提出观点的人而非观点本身'},
        {'name': '稻草人谬误', 'description': '曲解或夸大对方观点再反驳'},
        {'name': '虚假两难', 'description': '制造非此即彼的假象'},
        {'name': '滑坡谬误', 'description': '夸大某一步骤的连锁后果'},
        {'name': '循环论证', 'description': '结论出现在前提中'},
        {'name': '以偏概全', 'description': '基于不足样本得出一般结论'},
        {'name': '诉诸权威', 'description': '以权威观点作为最终论据'},
        {'name': '诉诸自然', 'description': '认为自然的就一定是好的'},
        {'name': '诉诸情感', 'description': '用情感替代逻辑论证'},
        {'name': '从众谬误', 'description': '以多数人认可为由论证'},
        {'name': '你也一样谬误', 'description': '以对方也犯错为由辩护'},
        {'name': '起源谬误', 'description': '以来源判定观点正误'},
        {'name': '合成谬误', 'description': '将部分性质推广到整体'},
        {'name': '分解谬误', 'description': '将整体性质归结到部分'},
        {'name': '赌徒谬误', 'description': '认为独立事件有相关性'},
    ]
    biases = [
        {'name': '确认偏误', 'description': '只找支持自己观点的证据'},
        {'name': '锚定效应', 'description': '过度依赖最先获得的信息'},
        {'name': '达克效应', 'description': '能力不足者高估自己'},
        {'name': '幸存者偏差', 'description': '忽略失败案例只关注成功'},
        {'name': '可得性启发', 'description': '以想起的容易程度判断概率'},
        {'name': '后见之明', 'description': '事后认为自己早预料到了'},
        {'name': '过度自信', 'description': '高估自己的判断准确度'},
        {'name': '沉没成本', 'description': '因已投入而继续错误决策'},
        {'name': '框架效应', 'description': '受表述方式影响判断'},
        {'name': '负面偏误', 'description': '负面信息影响大于正面'},
    ]
    return jsonify({
        'total_fallacies': len(fallacies),
        'total_biases': len(biases),
        'fallacies': fallacies,
        'biases': biases,
        'total': len(fallacies) + len(biases)
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)