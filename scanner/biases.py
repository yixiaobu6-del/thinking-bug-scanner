"""
思维漏洞扫描器 - 认知偏误检测规则
覆盖10种常见认知偏误

支持的中文检测模式包括：
1. 确认偏误
2. 锚定效应
3. 达克效应
4. 幸存者偏差
5. 可得性启发
6. 后见之明
7. 过度自信
8. 沉没成本谬误
9. 框架效应
10. 负面偏误
"""

import re


class BiasDetector:
    """认知偏误检测器"""

    def __init__(self):
        """初始化检测规则"""
        self.rules = self._initialize_rules()

    def _initialize_rules(self) -> list:
        """初始化所有检测规则"""
        return [
            # 1. 确认偏误
            {
                'name': '确认偏误',
                'name_en': 'Confirmation Bias',
                'description': '倾向于寻找和关注支持自己已有观点的信息，忽视反面证据',
                'severity': 'medium',
                'patterns': [
                    (r'(我一直.{0,8}(认为|觉得|相信|主张).{0,15}(再次|再一次|又|更加|进一步)(证明|证实|验证|说明))'),
                    (r'(这.{0,5}(不|难道不|不就|正好|恰恰).{0,8}(证明|说明|印证|证实).{0,10}(我说|我的|我之前|我一直)的)'),
                    (r'(早就.{0,6}(说过|知道|料到|想到).{0,10}(果然|果不其然|不出所料|看吧|对吧)'),
                ],
                'suggestion': '主动寻找与自己观点相反的证据（反面搜索），避免只收集支持自己的信息。'
            },
            # 2. 锚定效应
            {
                'name': '锚定效应',
                'name_en': 'Anchoring Effect',
                'description': '过度依赖最先获得的信息（锚点）来做出后续判断',
                'severity': 'low',
                'patterns': [
                    (r'(参考.{0,6}(去年|之前|以前|历史|上个月).{0,10}(数据|价格|标准|基准|水平).{0,15}(相比|对比|比较|参照))'),
                    (r'(以.{0,6}(为基准|为参照|为标准|作为锚点|作为参考点).{0,15}(调整|改动|修改|变动))'),
                ],
                'suggestion': '避免过度依赖初始信息作为判断基准。尝试从不同角度评估，获取更多独立信息源。'
            },
            # 3. 达克效应
            {
                'name': '达克效应',
                'name_en': 'Dunning-Kruger Effect',
                'description': '能力不足的人往往会高估自己，而真正有能力的人反而容易低估自己',
                'severity': 'low',
                'patterns': [
                    (r'(这.{0,6}(有|没|不).{0,6}(什么|啥).{0,6}(难的|复杂的|需要学的|了不起的|大不了的))'),
                    (r'(不就是.{0,8}(吗|嘛|罢了).{0,8}(我|我上|谁).{0,8}(也|都).{0,8}(行|可以|能)。?)'),
                    (r'(这么简单的事情|这么容易的东西|谁会不懂这个)'),
                ],
                'suggestion': '对一个领域的了解越浅，越容易低估其复杂性。请在深入学习和实践后再评估自己的水平。'
            },
            # 4. 幸存者偏差
            {
                'name': '幸存者偏差',
                'name_en': 'Survivorship Bias',
                'description': '只关注成功者或幸存者，而忽略了失败者的存在',
                'severity': 'high',
                'patterns': [
                    (r'(你看.{0,8}(那些人|他们|人家|那些成功的).{0,15}(不就|不都是|都是|也是).{0,10}(辍学|没学历|不努力|运气好|创业|辞职))'),
                    (r'(某某.{0,4}(也是|就是|不也是|不就是).{0,4}(这样|这么做|这么干|走这条路).{0,10}(成功|赚到|发了|成了))'),
                ],
                'suggestion': '不要只看成功案例。同样方法失败的人有多少？成功者的成功可能来自其他因素。'
            },
            {
                'name': '幸存者偏差',
                'name_en': 'Survivorship Bias',
                'description': '只关注成功者而忽视失败者',
                'severity': 'high',
                'patterns': [
                    (r'(那些成功.{0,6}(的|人士|者|的人).{0,15}(都是|都|也是|全都)(因|靠|通过|凭借))'),
                ],
                'suggestion': '检查那些不成功的人是否也采取了同样的策略。成功可能归因于其他因素。'
            },
            # 5. 可得性启发
            {
                'name': '可得性启发',
                'name_en': 'Availability Heuristic',
                'description': '以能想起类似事例的容易程度来判断事件发生的概率',
                'severity': 'low',
                'patterns': [
                    (r'(最近.{0,10}(好多|很多|频繁|经常).{0,10}(新闻|报道|听说|看到|遇到).{0,10}(所以|因此|可见).{0,10}(很常见|很多|越来越|到处都是|高风险))'),
                    (r'(我(身边|周围|认识)的.{0,10}(都|全|全是|全都|基本上).{0,10}(这样|如此|这个情况))'),
                ],
                'suggestion': '容易想起的案例不代表它更常见。请参考统计数据而非个人体验来评估概率。'
            },
            # 6. 后见之明
            {
                'name': '后见之明',
                'name_en': 'Hindsight Bias',
                'description': '在事情发生后认为自己在事前就已经知道结果',
                'severity': 'medium',
                'patterns': [
                    (r'(早就.{0,6}(知道|说过|料到|想到|预见|预感).{0,15}(会.{0,8}|结果.{0,8}|肯定.{0,8}|必然.{0,8}))'),
                    (r'(我(当初|之前|一开始).{0,8}(就说|就说过|就认为|就觉得|就知道|就猜到).{0,15}(肯定|一定|绝对|必然|早晚会).{0,8}(出问题|成功|失败))'),
                ],
                'suggestion': '请回忆在事前你有多确定这个结果。事后看来的"必然"在事前可能只是众多可能性之一。'
            },
            # 7. 过度自信
            {
                'name': '过度自信',
                'name_en': 'Overconfidence Effect',
                'description': '高估自己判断的准确性和预测能力',
                'severity': 'medium',
                'patterns': [
                    (r'(我(百分之百|绝对|肯定|一定|百分百|毫无疑问|毋庸置疑).{0,10}(确定|肯定|相信|认为|保证))'),
                    (r'(用.{0,4}(脚|膝盖).{0,8}(想|思考).{0,6}(都|也).{0,6}(知道|想到|明白))'),
                    (r'(想都别想|做梦都不可能出现|打死我也不信|一定是这样|绝对没错)'),
                ],
                'suggestion': '给自己的判断留一个误差空间。可以用概率思维来表达不确定度，而不是绝对化的断言。'
            },
            # 8. 沉没成本谬误
            {
                'name': '沉没成本谬误',
                'name_en': 'Sunk Cost Fallacy',
                'description': '因为已经投入了大量时间、金钱或精力，所以继续坚持明知不正确的决策',
                'severity': 'high',
                'patterns': [
                    (r'(已经(投入|花了|付出|用了|等了).{0,10}(这么|那么|如此).{0,8}(多|久|长时间|心血|精力|钱).{0,10}(放弃|停止|退出|算了|不做了).{0,10}(可惜|浪费|不甘心|不甘))'),
                    (r'(都.{0,6}(这一步|这个份|这个程度|这么久|这么多了).{0,10}(现在|这时候).{0,10}(放弃|退出|停止).{0,10}(可惜|浪费|不是白费了|前功尽弃))'),
                ],
                'suggestion': '过去的投入已经无法收回（沉没成本）。做决策时只考虑未来的收益和成本，不要让过去影响现在。'
            },
            # 9. 框架效应
            {
                'name': '框架效应',
                'name_en': 'Framing Effect',
                'description': '同一个问题因表述方式不同而产生不同的判断',
                'severity': 'low',
                'patterns': [
                    (r'(成功率.{0,10}(高达|达到|超过)|失败率.{0,10}(只有|低至|不到))'),
                    (r'(如果.{0,10}(不做|不尝试|不行动|不采用).{0,15}(将|会|可能).{0,10}(损失|错过|失去|落后))'),
                ],
                'suggestion': '尝试从相反框架重新表述问题。例如：如果是"90%存活率"，也想想"10%死亡率"。'
            },
            # 10. 负面偏误
            {
                'name': '负面偏误',
                'name_en': 'Negativity Bias',
                'description': '在同等强度下，负面信息对人的影响大于正面信息',
                'severity': 'low',
                'patterns': [
                    (r'(虽然.{0,10}(不错|还行|可以|好).{0,5}(但是|可是|不过|然而).{0,15}(问题|风险|缺陷|不足|缺憾|隐患|担忧))'),
                    (r'(好.{0,5}(是好|确实不错|还可以).{0,10}(但|不过|然而|可是).{0,10}(你.{0,6}要|你.{0,6}得|必须|一定|千万).{0,8}(注意|小心|当心|警惕))'),
                ],
                'suggestion': '主动记录和回顾正面事件，有意识地平衡对正面和负面信息的关注度。'
            },
        ]

    def detect(self, text: str) -> list:
        """
        检测文本中的认知偏误

        Args:
            text: 待检测文本

        Returns:
            检测到的偏误列表
        """
        results = []

        for rule in self.rules:
            for idx, pattern in enumerate(rule['patterns']):
                matches = re.finditer(pattern, text)
                for match in matches:
                    matched_text = match.group()

                    # 避免重复检测
                    is_duplicate = any(
                        r['name'] == rule['name'] and r['matched'] == matched_text
                        for r in results
                    )

                    if not is_duplicate:
                        char_pos = match.start()
                        context_start = max(0, char_pos - 15)
                        context_end = min(len(text), char_pos + len(matched_text) + 15)
                        context = text[context_start:context_end]

                        results.append({
                            'type': 'bias',
                            'name': rule['name'],
                            'name_en': rule['name_en'],
                            'description': rule['description'],
                            'severity': rule['severity'],
                            'matched': matched_text,
                            'context': f"...{context}...",
                            'position': char_pos,
                            'suggestion': rule['suggestion'],
                            'pattern_index': idx
                        })

        # 按位置排序
        results.sort(key=lambda x: x['position'])
        return results


if __name__ == '__main__':
    detector = BiasDetector()

    test_texts = [
        "我就知道会这样，我早就说过这个方案行不通。",
        "你看那些成功的企业家，都是辍学创业的。",
        "已经投入了这么多时间，现在放弃太可惜了。",
        "最近看到很多这样的新闻，所以这种事情很常见。",
        "我百分之百确定这个方案是正确的。"
    ]

    for text in test_texts:
        print(f"\n=== 测试文本 ===")
        print(f"内容: {text}")
        results = detector.detect(text)
        if results:
            for r in results:
                print(f"检测到 [{r['severity']}] {r['name']}: {r['description']}")
        else:
            print("未检测到认知偏误")