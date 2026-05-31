# 思维漏洞扫描器

检测论证过程中的逻辑谬误和认知偏误，提升思维质量。

## 项目简介

思维漏洞扫描器是一款帮助用户识别思维中逻辑缺陷和认知偏误的工具。无论是日常思考、写作论证还是决策过程，都可以通过本工具来检查是否存在常见的逻辑谬误和认知偏误。

## 核心功能

- **逻辑谬误检测**：覆盖15种以上常见逻辑谬误
- **认知偏误检测**：覆盖10种以上常见认知偏误
- **Web交互界面**：基于Web的可视化分析工具
- **实时扫描**：输入即检测，即时反馈
- **详细报告**：包含问题定位、类型说明、改进建议

## 技术架构

```
思维漏洞扫描器/
├── scanner/
│   ├── fallacies.py     # 逻辑谬误检测规则
│   ├── biases.py        # 认知偏误检测规则
│   └── checker.py       # 综合检查器
├── templates/
│   └── index.html       # Web界面
├── web_app.py           # Flask/FastAPI Web应用
├── requirements.txt
└── README.md
```

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 启动Web服务

```bash
python web_app.py
```

访问 `http://localhost:5000` 即可使用。

### 命令行使用

```python
from scanner.checker import ThinkingChecker

checker = ThinkingChecker()
text = "因为大多数人都这么做，所以这样做是对的。"

results = checker.scan(text)
for result in results:
    print(f"类型: {result['type']}")
    print(f"问题: {result['issue']}")
    print(f"建议: {result['suggestion']}")
```

## 支持的逻辑谬误（15种）

| 编号 | 谬误名称 | 中文名称 | 说明 |
|------|----------|----------|------|
| 1 | Ad Hominem | 人身攻击 | 攻击提出观点的人而非观点本身 |
| 2 | Straw Man | 稻草人谬误 | 曲解或夸大对方观点再反驳 |
| 3 | False Dilemma | 虚假两难 | 制造非此即彼的假象 |
| 4 | Slippery Slope | 滑坡谬误 | 夸大某一步骤的连锁后果 |
| 5 | Circular Reasoning | 循环论证 | 结论出现在前提中 |
| 6 | Hasty Generalization | 以偏概全 | 基于不足样本得出一般结论 |
| 7 | Appeal to Authority | 诉诸权威 | 以权威观点作为最终论据 |
| 8 | Appeal to Nature | 诉诸自然 | 认为自然的就一定是好的 |
| 9 | Appeal to Emotion | 诉诸情感 | 用情感替代逻辑论证 |
| 10 | Bandwagon | 从众效应 | 以多数人认可为由论证 |
| 11 | Tu Quoque | 你也一样 | 以对方也犯错为由辩护 |
| 12 | Genetic Fallacy | 起源谬误 | 以来源判定观点正误 |
| 13 | Composition Fallacy | 合成谬误 | 将部分性质推广到整体 |
| 14 | Division Fallacy | 分解谬误 | 将整体性质归结到部分 |
| 15 | The Gambler's Fallacy | 赌徒谬误 | 认为独立事件有相关性 |

## 支持的认知偏误（10种）

| 编号 | 偏误名称 | 中文名称 | 说明 |
|------|----------|----------|------|
| 1 | Confirmation Bias | 确认偏误 | 倾向于寻找证实已有观点的信息 |
| 2 | Anchoring Effect | 锚定效应 | 过度依赖最先获得的信息 |
| 3 | Dunning-Kruger Effect | 达克效应 | 能力低者高估自己，高者低估自己 |
| 4 | Survivorship Bias | 幸存者偏差 | 只关注幸存者而忽视失败者 |
| 5 | Availability Heuristic | 可得性启发 | 以想起的容易程度判断概率 |
| 6 | Hindsight Bias | 后见之明 | 事后认为自己早预测到了 |
| 7 | Overconfidence Effect | 过度自信 | 高估自己的判断准确性 |
| 8 | Sunk Cost Fallacy | 沉没成本谬误 | 因已投入而继续错误决策 |
| 9 | Framing Effect | 框架效应 | 受问题表述方式影响判断 |
| 10 | Negativity Bias | 负面偏误 | 负面信息比正面信息影响更大 |

## 检测规则格式

每条检测规则包含：

```python
{
    'name': '谬误/偏误名称',
    'description': '简要说明',
    'patterns': ['匹配模式列表'],
    'severity': 'high/medium/low',
    'suggestion': '改进建议'
}
```

## 应用场景

- **写作检查**：文章论证的逻辑完整性检测
- **决策辅助**：重要决策前的思维偏误排查
- **辩论准备**：检查自身论证逻辑，预测对方谬误
- **日常思考**：培养批判性思维习惯

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request。