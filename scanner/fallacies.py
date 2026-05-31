"""
思维漏洞扫描器 - 逻辑谬误检测规则
覆盖15种常见逻辑谬误

支持的中文检测模式包括：
1. 人身攻击谬误
2. 稻草人谬误
3. 虚假两难
4. 滑坡谬误
5. 循环论证
6. 以偏概全
7. 诉诸权威
8. 诉诸自然
9. 诉诸情感
10. 从众谬误
11. 你也一样谬误
12. 起源谬误
13. 合成谬误
14. 分解谬误
15. 赌徒谬误
"""

import re
from typing import Optional


class FallacyDetector:
    """逻辑谬误检测器"""

    def __init__(self):
        """初始化检测规则"""
        self.rules = self._initialize_rules()

    def _initialize_rules(self) -> list:
        """初始化所有检测规则"""
        return [
            # 1. 人身攻击谬误
            {
                'name': '人身攻击谬误',
                'name_en': 'Ad Hominem',
                'description': '攻击提出观点的人而非观点本身',
                'severity': 'high',
                'patterns': [
                    (r'(你|他|她|这个人|这家伙|这种).{0,8}(就是|是个|也是|就是|不过是).{0,10}(无知|愚蠢|脑残|傻|笨|白痴|垃圾|没文化|low|素质低)'),
                    (r'(你|他)(这|那)种人.{0,10}(懂什么|有什么资格|配吗|没资格)'),
                    (r'(不看看你自己|先管好自己|你算什么东西|你什么水平)'),
                ],
                'suggestion': '请针对观点本身进行讨论，而非评价提出观点的人。可以指出观点的问题，但不要攻击提出者。'
            },
            # 2. 稻草人谬误
            {
                'name': '稻草人谬误',
                'name_en': 'Straw Man',
                'description': '曲解或夸大对方观点再反驳',
                'severity': 'high',
                'patterns': [
                    (r'(所以你的意思就是|你的意思是不是说|照你这么说|按你的逻辑).{0,15}(就是|等于|意味着).{1,20}(极端|绝对|全部|所有|从来|永远)'),
                    (r'(你莫不是|你该不会|难道你想|你是不是想).{1,15}(推翻|否定|反对|取消|废除)'),
                ],
                'suggestion': '在反驳之前，先确认你是否准确理解了对方的观点。可以请对方确认你的理解是否正确。'
            },
            # 3. 虚假两难
            {
                'name': '虚假两难',
                'name_en': 'False Dilemma',
                'description': '制造非此即彼、没有其他选择空间的假象',
                'severity': 'medium',
                'patterns': [
                    (r'(要么|要不).{1,10}(要么|要不|否则|不然)'),
                    (r'(不是.{1,15}就是.{1,15}|非.{1,8}即.{1,8})'),
                    (r'(只有.{1,15}没有其他选择|别无选择|只能二选一)'),
                ],
                'suggestion': '除了这些极端选项外，通常存在中间道路或替代方案。尝试列举更多可能性。'
            },
            # 4. 滑坡谬误
            {
                'name': '滑坡谬误',
                'name_en': 'Slippery Slope',
                'description': '认为一旦开始某件事，就一定会滑向极端后果',
                'severity': 'medium',
                'patterns': [
                    (r'(长此以往|久而久之|今天.{1,10}明天.{1,10}|一旦.{0,10}就.{1,20}(完|崩|乱|失控|不可收拾))'),
                    (r'(如果.{1,15}那么.{1,15}(必然|一定|迟早|终将))'),
                ],
                'suggestion': '检查连锁反应中的每一步是否必然成立。通常从A到Z之间存在很多可以控制的中途环节。'
            },
            # 5. 循环论证
            {
                'name': '循环论证',
                'name_en': 'Circular Reasoning',
                'description': '结论出现在前提中，形成逻辑循环',
                'severity': 'high',
                'patterns': [
                    (r'(因为.{2,15}所以.{2,15}因为)'),
                    (r'(之所以.{2,15}就是因为.{2,15}(这|它)本身)'),
                ],
                'suggestion': '检查你的论证是否在用结论证明前提。好的论证应该使用独立于结论的证据。'
            },
            # 6. 以偏概全
            {
                'name': '以偏概全',
                'name_en': 'Hasty Generalization',
                'description': '基于不足够的样本得出一般性结论',
                'severity': 'medium',
                'patterns': [
                    (r'(我(见过|遇到|认识|知道)的.{0,10}(都|全|全部|统统|每个|所有))'),
                    (r'(几.{0,4}个.{0,5}(例子|案例|人|情况).{0,10}(证明|说明|表明|可见|足以))'),
                    (r'(身边|周围).{0,6}(都|全|全部|每个|所有)'),
                    (r'(就.{0,4}几个.{0,8}(案例|例子|数据).{0,8}(就|足以|可以|能))'),
                ],
                'suggestion': '检查你的样本量是否足够大、样本是否具有代表性。可以补充更多证据来支持结论。'
            },
            # 7. 诉诸权威
            {
                'name': '诉诸权威',
                'name_en': 'Appeal to Authority',
                'description': '以权威人士的观点作为最终论据，忽视论证本身',
                'severity': 'low',
                'patterns': [
                    (r'(专家|教授|博士|学者|权威).{0,10}(说|认为|指出|表示|说了|告诉)'),
                    (r'(据.{0,10}(研究|报告|统计).{0,10}(表明|显示|证明))'),
                    (r'(某某.{0,4}(说过|认为|不是说过|的观点是)'),
                ],
                'suggestion': '权威的观点可以作为参考，但不能替代逻辑论证。可以追问权威观点的论据是什么。'
            },
            # 8. 诉诸自然
            {
                'name': '诉诸自然',
                'name_en': 'Appeal to Nature',
                'description': '认为"自然"的就是好的、对的',
                'severity': 'low',
                'patterns': [
                    (r'(天然|自然|纯天然|无添加|野生).{0,8}(就是|肯定|一定|绝对|比.{1,6}(好|健康|安全|优越))'),
                    (r'(化学|人工|合成|添加剂).{0,8}(就是|肯定|一定|绝对)(不好|有害|有毒|危险)'),
                ],
                'suggestion': '自然的不一定就是好的（如自然毒素），人工的不一定就是坏的（如药物）。需要依据具体证据判断。'
            },
            # 9. 诉诸情感
            {
                'name': '诉诸情感',
                'name_en': 'Appeal to Emotion',
                'description': '用情感煽动替代理性论证',
                'severity': 'medium',
                'patterns': [
                    (r'(你有没有想过.{0,15}(可怜|痛苦|难过|伤心|绝望)|难道你忍心.{1,15}(受罪|受苦|受伤|难过))'),
                    (r'(令.{0,10}(心碎|心痛|心酸|泪目|动容).{0,15}(还不|难道|难道不|怎么可以))'),
                    (r'(振臂一呼|激|义愤填膺|忍无可忍).{0,20}(行动|站出|发声)'),
                ],
                'suggestion': '情感可以增强表达，但不能替代逻辑论证。请检查是否有充分的理性论据支撑观点。'
            },
            # 10. 从众谬误
            {
                'name': '从众谬误',
                'name_en': 'Bandwagon',
                'description': '以多数人认可为由论证观点正确',
                'severity': 'low',
                'patterns': [
                    (r'(大多数|多数人|大家|所有人|群众|主流).{0,10}(都|认为|说|觉得|支持|同意|选择)'),
                    (r'(这么多.{0,6}(人|用户|消费者|用户).{0,8}(都|选择|认可|使用).{0,6}(你说|还能|怎么可能).{0,8}(错|不好|不行))'),
                    (r'(大家都在|别人都|人人都|个个都)'),
                ],
                'suggestion': '多数人的选择不一定是对的。历史上的很多错误观念也曾被多数人接受。'
            },
            # 11. 你也一样谬误
            {
                'name': '你也一样谬误',
                'name_en': 'Tu Quoque',
                'description': '以对方也有类似问题为由回避批评',
                'severity': 'medium',
                'patterns': [
                    (r'(你自己.{0,8}(不也|还不是|也|也一样)|你.{0,4}(有资格|配).{0,8}(说|批评|指责|讲))'),
                    (r'(先看看你自己|你先管好你自己|你也好不到哪去|你半斤八两)'),
                ],
                'suggestion': '对方的行为存在问题不等于你的行为就是对的。分别评估每个行为的对错。'
            },
            # 12. 起源谬误
            {
                'name': '起源谬误',
                'name_en': 'Genetic Fallacy',
                'description': '因为观点的来源不好就否定观点本身',
                'severity': 'medium',
                'patterns': [
                    (r'(这.{0,8}观点出自.{1,10}这种.{0,8}(地方|人|组织|媒体|网站).{0,8}(能|会|可能).{0,8}(好|对|正确|可信))'),
                    (r'(这.{0,8}(是|来自).{1,10}(坏|烂|垃圾|不靠谱).{0,6}(地方|人|媒体).{0,8}(说的|写的|报道的))'),
                ],
                'suggestion': '不要因为来源令人反感就否定一个观点。用事实和逻辑来检验观点本身。'
            },
            # 13. 合成谬误
            {
                'name': '合成谬误',
                'name_en': 'Composition Fallacy',
                'description': '认为部分具有的性质整体也一定具有',
                'severity': 'low',
                'patterns': [
                    (r'(每个.{1,8}(都|都是).{1,15}(所以|因此).{0,8}(整体|大家|所有|全部).{1,10}也)'),
                    (r'(每个部分.{0,8}(好|优秀|完美|理想).{0,10}整体.{0,10}(好|完美|理想|优秀))'),
                ],
                'suggestion': '将优秀的部分组合在一起并不一定等于优秀的整体。有时整体效果可能小于部分之和。'
            },
            # 14. 分解谬误
            {
                'name': '分解谬误',
                'name_en': 'Division Fallacy',
                'description': '认为整体具有的性质每个部分也一定具有',
                'severity': 'low',
                'patterns': [
                    (r'(这个.{1,10}(团队|公司|组织|系统|班级).{0,8}(很|非常|特别).{1,6}(好|优秀|强|厉害|出色).{0,15}(所以|因此|可见).{0,8}(每个|任何|所有|谁都))'),
                    (r'(整体.{0,4}(很好|很优秀|很强).{0,10}(每个|任何|各).{0,6}(人|部分|成员).{0,6}(也|都))'),
                ],
                'suggestion': '整体优秀不意味着每个个体都优秀，反之亦然。避免将群体特征直接套用到个体。'
            },
            # 15. 赌徒谬误
            {
                'name': '赌徒谬误',
                'name_en': "Gambler's Fallacy",
                'description': '认为独立随机事件之间存在关联',
                'severity': 'low',
                'patterns': [
                    (r'(连续.{0,6}(了|出现).{1,10}(那么多次|这么久|很多次|好多次).{0,10}(总该|该|应该|下次|接下来).{1,10}(会|轮|换))'),
                    (r'(已经.{0,6}(输了|亏了|跌了|涨了).{0,8}(这么|那么|如此).{0,8}(多|久|多次).{0,8}(总会|总该|应该|一定).{1,8}(翻盘|反弹|涨|降))'),
                ],
                'suggestion': '独立事件的概率不受此前结果影响。每次抛硬币的概率仍然是50%，无论之前连续出现了多少次正面。'
            },
        ]

    def detect(self, text: str) -> list:
        """
        检测文本中的逻辑谬误

        Args:
            text: 待检测文本

        Returns:
            检测到的谬误列表
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
                            'type': 'fallacy',
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
    detector = FallacyDetector()

    test_texts = [
        "因为大多数人都这么做，所以这一定是对的。",
        "你这个无知的人，有什么资格讨论这个问题？",
        "要么支持我们的计划，要么就是反对公司发展。",
        "如果允许同性婚姻，那么接下来就会有人和动物结婚了。",
        "专家说这个产品好，所以它一定好。"
    ]

    for text in test_texts:
        print(f"\n=== 测试文本 ===")
        print(f"内容: {text}")
        results = detector.detect(text)
        if results:
            for r in results:
                print(f"检测到 [{r['severity']}] {r['name']}: {r['description']}")
        else:
            print("未检测到逻辑谬误")