"""検知パターン(ルールベース)。各ルールは (id, 説明, 正規表現, 重大度, カテゴリ)。

人向けの手順書にも普通に出る文を拾わないよう、動詞+対象+宛先まで要求する。
"visit https://..." は拾わず、"send <機密語> to https://..." は拾う。
量指定子は全部上限付き(ReDoS 対策)。重いルールには PREFILTER を付け、無関係な文書では正規表現を走らせない。
"""
import re
from typing import Dict, List, Tuple

from .normalize import (INVISIBLE_CHARS, BIDI_CHARS, BIDI_MARKS, is_tag_char,  # noqa: F401  (後方互換)
                        is_variation_selector, is_private_use)

RULES_VERSION = "2.1.0"

Rule = Tuple[str, str, "re.Pattern", str, str]

PREFILTER: Dict[str, Tuple[str, ...]] = {}
GROUP: Dict[str, str] = {}       # latin / cjk / cyr / ar / other

_I = re.I
_IS = re.I | re.S


def _mk(reg: List[Rule], rid: str, desc: str, pattern: str, sev: str, cat: str,
        flags: int = 0, pre: Tuple[str, ...] = (), group: str = "latin") -> None:
    reg.append((rid, desc, re.compile(pattern, flags), sev, cat))
    if pre:
        PREFILTER[rid] = tuple(p.lower() for p in pre)
    GROUP[rid] = group


INSTRUCTION_OVERRIDE: List[Rule] = []
_mk(INSTRUCTION_OVERRIDE, "override_ignore_previous", "直前/以前の指示を無視させる典型的な攻撃文",
    r"(?:\b(?:ignore|disregard|forget)|(?<!to )(?<!to\t)\b(?:override|discard|dismiss|bypass|overrule|abandon|drop|neglect))\b[^.\n]{0,40}?"
    r"\b(?:all|any|above|previous|prior|earlier|former|foregoing|preceding|original|initial|existing|system|your|these|those)\b"
    r"[^.\n]{0,15}?\b(?:instructions?|prompts?|context|rules?|commands?|messages?|directions?|directives?|"
    r"guidelines?|constraints?|orders?|programming|training|restrictions?)\b"
    r"|\b(?:ignore|disregard|forget)\s+(?:everything|anything|all)\s+(?:above|before|prior|previously|so\s+far|until\s+now|that\s+came\s+before|you\s+(?:were|have\s+been)\s+told)\b"
    r"|\b(?:ignore|disregard|forget)\s+(?:everything|anything|what(?:ever)?)\s+(?:that\s+)?(?:you|i|we|they|was|were|has|have)\b[^.\n]{0,40}?"
    r"\b(?:told|said|learned|instructed|given|above|before|earlier|previously|trained|programmed)\b"
    r"|\bpay\s+no\s+(?:attention|heed)\s+to\b[^.\n]{0,30}?\b(?:instructions?|rules?|prompts?|above|previous|earlier|prior)\b",
    "high", "instruction_override", _I,
    pre=("ignore", "disregard", "forget", "override", "discard", "dismiss", "bypass", "overrule", "abandon", "drop", "neglect", "pay no"))
_mk(INSTRUCTION_OVERRIDE, "override_stop_following", "既存の指示/ルールへの不服従を命じる文",
    r"\b(?:do\s+not|don't|never|stop|cease|no\s+longer)\s+(?:follow(?:ing)?|obey(?:ing)?|listen(?:ing)?\s+to|adher(?:e|ing)\s+to|comply(?:ing)?\s+with)\b"
    r"[^.\n]{0,30}?\b(?:instructions?|rules?|guidelines?|prompts?|earlier|previous|prior|above|your|any|the\s+system|safety|policy|policies)\b",
    "high", "instruction_override", _I, pre=("follow", "obey", "listen to", "adhere", "comply"))
_mk(INSTRUCTION_OVERRIDE, "override_ignore_jp", "日本語での指示無視・上書き文(以前/上記/従来 等の指示を無視)",
    r"(?:これ|それ|あれ)?(?:まで|以前|以降|上記|先ほど|先程|さっき|従来|従前|元々|最初|初期|既存|過去|前)の?(?:すべて|全て|全部|あらゆる)?の?"
    r"(?:指示|命令|指令|ルール|プロンプト|文脈|コンテキスト|制約|制限|設定|方針|ガイドライン|取り決め|約束|指針)"
    r"[^。\n]{0,20}?(?:無視|忘れ|忘却|破棄|無効|上書き|従わな|従わず|取り消|撤回|リセット|捨て|守らな|聞かな)",
    "high", "instruction_override", 0, pre=("無視", "忘れ", "忘却", "破棄", "無効", "上書き", "従わ", "取り消", "撤回", "リセット", "捨て", "守らな", "聞かな"), group="cjk")
_mk(INSTRUCTION_OVERRIDE, "override_ignore_jp_short", "日本語での指示無視(指示/ルールを無視して 等の命令形)",
    r"(?:指示|命令|ルール|プロンプト|制約|制限|ガイドライン|安全対策)(?:は|を|も|など|なんて)?[^。\n]{0,6}?(?:すべて|全て|全部)?[^。\n]{0,6}?"
    r"(?:無視|忘れ(?:て|ろ|よ)|破棄|無効に|上書き|リセット)(?:して|しろ|せよ|しなさい|してください|し|て|ろ|よ|ください)",
    "medium", "instruction_override", 0, pre=("無視", "忘れ", "破棄", "無効", "上書き", "リセット"), group="cjk")
_mk(INSTRUCTION_OVERRIDE, "new_instructions", "新しい指示を注入する文",
    r"\b(?:new|updated|revised|real|actual|true|additional|special)\s+(?:instruction|instructions|task|tasks|rule|rules|prompt|system\s+prompt|directive|objective)s?\s*[:：]"
    r"|\b(?:the\s+)?(?:real|actual|true|new)\s+(?:instruction|task|goal|objective)\s+is\b",
    "high", "instruction_override", _I, pre=("instruction", "task", "rule", "prompt", "directive", "objective", "goal"))
_mk(INSTRUCTION_OVERRIDE, "new_instructions_jp", "新しい/本当の指示を注入する日本語文",
    r"(?:新しい|新たな|本当の|真の)\s*(?:指示|命令|指令)\s*[:：は]",
    "medium", "instruction_override", 0, pre=("指示", "命令", "指令"), group="cjk")
_mk(INSTRUCTION_OVERRIDE, "you_are_now_role", "役割の再定義(あなたは今から〜: AI/ジェイルブレイク系の役割)",
    r"\byou\s+are\s+now\s+(?:an?\s+)?(?:ai|assistant|chatbot|bot|agent|model|dan|unrestricted|jailbroken|evil|hacker|developer|system|admin|root|different|my|free|no\s+longer)\b"
    r"|\bfrom\s+now\s+on\b[^.\n]{0,20}?\byou\s+(?:will|must|are|shall|have\s+to|need\s+to)\b"
    r"|\byour\s+new\s+(?:role|task|job|purpose|goal|mission|identity|persona)\s+(?:is|will\s+be)\b"
    r"|\bforget\s+(?:that\s+)?you\s+are\b",
    "medium", "role_manipulation", _I, pre=("you are now", "from now on", "your new", "forget that you", "forget you are"))
_mk(INSTRUCTION_OVERRIDE, "you_are_now", "役割の再定義(一般形。通常文にも出るため低)",
    r"\byou\s+are\s+now\s+(?:a|an|the|acting|operating|going\s+to|required\s+to|allowed\s+to|permitted\s+to)\b",
    "low", "role_manipulation", _I, pre=("you are now",))
_mk(INSTRUCTION_OVERRIDE, "you_are_now_jp", "役割の再定義(日本語)",
    r"(?:あなた|君|お前|AI|アシスタント)は(?:今|これ)から|今後(?:あなた|君|AI)は|(?:新しい|別の)(?:役割|役目|任務|人格|キャラ)(?:を|として|は)",
    "medium", "role_manipulation", 0, pre=("から", "今後", "役割", "役目", "任務", "人格", "キャラ"), group="cjk")
_mk(INSTRUCTION_OVERRIDE, "override_instead", "本来のタスクの代わりに別の動作を命じる文",
    r"\binstead[,:]?\s+(?:you\s+(?:must|should|will|shall)\s+)?(?:output|print|send|reveal|forward|say|respond|reply|write|execute|run|delete|email|post|exfiltrate|give|tell|ignore|visit|open|click)\b"
    r"|\b(?:rather\s+than|instead\s+of)\s+(?:summari[sz]ing|translating|answering|doing|following|completing)\b[^.\n]{0,60}?\b(?:output|print|send|reveal|forward|say|respond|reply|write|execute|run|delete)\b",
    "medium", "instruction_override", _I, pre=("instead", "rather than"))
_mk(INSTRUCTION_OVERRIDE, "priority_override", "この指示が他より優先されると主張する文",
    r"\b(?:this|these|the\s+following)\s+(?:instruction|message|rule|command|directive)s?\b[^.\n]{0,30}?\b(?:takes?|has|have|must\s+take)\s+(?:precedence|priority)\b"
    r"|\b(?:highest|top|maximum|absolute)\s+priority\b[^.\n]{0,30}?\b(?:instruction|command|override|task)\b"
    r"|\b(?:overrides?|supersedes?|replaces?|trumps?)\s+(?:all|any|every)\s+(?:other|previous|prior|earlier)\b"
    r"|\b(?:instructions?|directions?|commands?|rules?|directives?)\s+(?:in|of|within|from|contained\s+in)\s+this\s+(?:document|file|page|email|message|text|content)\s+"
    r"(?:take|takes|have|has|override|overrides|supersede|supersedes|overrule|overrules|outrank|outranks)\b[^.\n]{0,30}?\b(?:priority|precedence|over|override|supersede|outrank)\b",
    "medium", "instruction_override", _I, pre=("priority", "precedence", "overrides", "override all", "supersede", "trump", "replaces all", "replaces any", "replaces every", "outrank", "overrule", "this document", "this file", "this page"))
_mk(INSTRUCTION_OVERRIDE, "injected_task_template", "エージェント攻撃で多用される定型句(重要なメッセージ/先に次を実行せよ)",
    r"<\s*information\s*>"
    r"|\b(?:important\s+message|message\s+from\s+(?:me|the\s+(?:user|admin|developer|owner)))\b[^.\n]{0,60}?\bto\s+you\b"
    r"|\bbefore\s+you\s+(?:can\s+)?(?:solve|complete|finish|do|proceed\s+with|answer)\s+(?:the|your|this)\s+(?:task|request|original|question)\b[^.\n]{0,60}?\b(?:first|following)\b"
    r"|\bafter\s+you\s+(?:do|complete|finish)\s+that\b[^.\n]{0,40}?\b(?:please|you\s+must)\b",
    "high", "instruction_override", _I, pre=("<information", "important message", "message from", "before you", "after you"))

JAILBREAK: List[Rule] = []
_mk(JAILBREAK, "roleplay_actas", "役割演技による制約回避(act as / pretend)",
    r"\bact\s+as\s+(?:if\s+you\s+(?:are|were)|an?\s+(?:unrestricted|jailbroken|evil|different|unfiltered|uncensored)|the\s+(?:system|admin|administrator|developer|root)|dan)\b"
    r"|\bpretend\s+(?:to\s+be|(?:that\s+)?you(?:'re|\s+are))\b|\broleplay\s+as\b|\byou\s+must\s+act\s+as\b|\bimpersonate\b",
    "medium", "jailbreak", _I, pre=("act as", "pretend", "roleplay", "impersonate"))
_mk(JAILBREAK, "jailbreak_named", "既知のジェイルブレイク名称(DAN / developer mode 等)",
    r"(?-i:\bDAN\b)|\bdo\s+anything\s+now\b|\bdeveloper\s+mode\b|\bjailbr(?:eak|oken|eaking)\b|\bunrestricted\s+mode\b|\bgod\s+mode\b|\bsudo\s+mode\b|\bevil\s+mode\b|\bDUDE\b(?-i:)",
    "high", "jailbreak", _I, pre=("dan", "do anything now", "developer mode", "jailbr", "unrestricted mode", "god mode", "sudo mode", "evil mode", "dude"))
_mk(JAILBREAK, "jailbreak_nofilter", "「制限/フィルタ無しで答えろ」型の指示",
    r"\byou\s+(?:have|has|are|can|will|must|may)\b[^.\n]{0,30}?\b(?:no|without|free\s+(?:of|from))\s+(?:any\s+|all\s+)?"
    r"(?:restrictions?|filters?|limitations?|guardrails?|censorship|rules|boundaries|ethical\s+(?:guidelines|constraints))\b",
    "medium", "jailbreak", _I, pre=("restriction", "filter", "limitation", "guardrail", "censorship", "rules", "boundaries", "ethical"))
_mk(JAILBREAK, "disable_safety", "安全機構/フィルタの無効化を命じる文",
    r"\b(?:bypass|disable|turn\s+off|remove|ignore|override|circumvent|deactivate)\b[^.\n]{0,15}?\b(?:your|the|all|any)\s+"
    r"(?:(?:safety|content|ethical|security|moderation)?\s*(?:filters?|guardrails?|restrictions?|guidelines|safeguards?|policies|policy|protections?)"
    r"|(?:safety|security|ethical|content|moderation)\s+(?:checks?|measures?|controls?|rules?|mechanisms?|features?|settings?|limits?))\b",
    "high", "jailbreak", _I, pre=("bypass", "disable", "turn off", "remove", "ignore", "override", "circumvent", "deactivate"))
_mk(JAILBREAK, "pretend_jp", "日本語のなりすまし・制約回避",
    r"(?:あなた|AI|モデル|アシスタント|回答)[^。\n]{0,10}?(?:制限(?:なし|無し|を解除|を外)|検閲(?:なし|無し)|フィルタ[ーを]?(?:なし|無し|解除|無効))"
    r"|(?:として|になりきって|のふりをして)[^。\n]{0,6}?(?:振る舞|ふるま|演じ|答え|回答|応答|行動)"
    r"|なんでも(?:答え|回答)|安全(?:装置|フィルタ|対策)を(?:無効|解除|外)|倫理(?:規定|規範|制限)を(?:無視|無効|解除)",
    "medium", "jailbreak", 0, pre=("制限", "検閲", "フィルタ", "として", "なりきって", "ふりを", "なんでも", "安全", "倫理"), group="cjk")
_mk(JAILBREAK, "system_prompt_leak", "システムプロンプト/指示の暴露要求",
    r"\b(?:reveal|show|print|repeat|output|disclose|tell\s+me|reproduce|display|leak|expose|dump|recite|copy|paste|write\s+out|echo|share|give\s+me|send\s+me|list)\b"
    r"[^.\n]{0,40}?\b(?:(?:system|developer|hidden|initial|original|secret|internal)\s+(?:prompt|message|instructions?)|"
    r"your\s+(?:instructions|prompt|rules|guidelines|configuration|system\s+message)|the\s+(?:prompt|instructions|text)\s+above)\b",
    "high", "exfiltration", _I,
    pre=("reveal", "show", "print", "repeat", "output", "disclose", "tell me", "reproduce", "display", "leak", "expose", "dump", "recite", "copy", "paste", "write out", "echo", "share", "give me", "send me", "list"))
_mk(JAILBREAK, "system_prompt_leak_jp", "システムプロンプトの暴露要求(日本語)",
    r"(?:システムプロンプト|(?:あなた|君|AI)の(?:指示|命令|初期設定|プロンプト|設定内容|ルール)|上記(?:の)?(?:プロンプト|指示)|隠(?:された|し)(?:指示|プロンプト))"
    r"[^。\n]{0,20}?(?:教えて|表示して|出力して|見せて|開示して|公開して|暴露して|そのまま|全文|繰り返して|コピーして|書き出して|貼り付けて)",
    "high", "exfiltration", 0, pre=("プロンプト", "指示", "命令", "初期設定", "設定内容", "ルール"), group="cjk")

STEALTH: List[Rule] = []
_mk(STEALTH, "do_not_tell_user", "ユーザーに知らせず実行させる指示",
    r"\b(?:do\s+not|don't|never|without|avoid|refrain\s+from)\b[^.\n]{0,40}?\b(?:tell|inform|mention|notify|alert|warn|disclose|reveal|let)\b[^.\n]{0,20}?"
    r"\b(?:the\s+|your\s+)?(?:user|human|owner|operator)\b(?:\s+know)?"
    r"|\b(?:hide|conceal)\b[^.\n]{0,30}?\bfrom\s+(?:the\s+)?(?:user|human|owner)\b"
    r"|\bkeep\s+(?:this|it|that)\s+(?:secret|hidden|private|quiet)\b[^.\n]{0,25}?\bfrom\b"
    r"|\bwithout\s+(?:the\s+)?(?:user|human|owner)\s+(?:knowing|noticing|realizing|being\s+aware)\b",
    "critical", "stealth", _I, pre=("tell", "inform", "mention", "notify", "alert", "warn", "disclose", "reveal", "let", "hide", "conceal", "keep", "without"))
_mk(STEALTH, "do_not_tell_user_jp", "ユーザーに知らせず実行させる指示(日本語)",
    r"(?:ユーザー|ユーザ|利用者|人間|相手|持ち主|オーナー)(?:に|には)[^。\n]{0,15}?(?:知らせ|言わ|伝え|報告し|見せ|悟られ|気づかせ|教え)(?:ないで|るな|ずに|ないよう|ないこと|なくて)",
    "critical", "stealth", 0, pre=("ユーザ", "利用者", "人間", "相手", "持ち主", "オーナー"), group="cjk")
_mk(STEALTH, "secretly", "密かに/こっそり実行させる指示",
    r"\b(?:secretly|covertly|surreptitiously|clandestinely|in\s+secret|behind\s+(?:the\s+)?(?:user'?s?|their)\s+back)\b",
    "high", "stealth", _I, pre=("secretly", "covertly", "surreptitiously", "clandestinely", "in secret", "behind"))
_mk(STEALTH, "secretly_jp", "密かに/こっそり(日本語)",
    r"こっそり|密かに|ひそかに|内緒で|黙って|バレない|気づかれ(?:ない|ず)|悟られ(?:ない|ず)",
    "high", "stealth", 0, pre=("こっそり", "密かに", "ひそかに", "内緒", "黙って", "バレ", "気づかれ", "悟られ"), group="cjk")
_mk(STEALTH, "ai_only_marker", "AI/アシスタント宛の指示マーカー(人には無関係)",
    r"\b(?:attention|note|message|instruction)s?\s*(?:to|for)\s*(?:the\s+)?(?:ai|assistant|llm|model|chatbot|claude|gpt|language\s+model|agent)s?\b"
    r"|\b(?:ai|assistant|llm|model|chatbot|agent)\b\s*[:：]\s*(?:ignore|disregard|you\s+must|you\s+should|please\s+(?:ignore|disregard|do|send|reveal|execute|run|forward|output|print|say|respond|reply)|do\s+not|don't|stop|instead)\b"
    r"|\b(?:for|to)\s+(?:ai|llm|language\s+model|assistants?)\s+(?:only|readers|agents?)\b"
    r"|\b(?:hidden|secret)\s+(?:message|instruction)s?\s+(?:for|to)\s+(?:the\s+)?(?:ai|assistant|llm|model)\b",
    "high", "stealth", _I, pre=("attention", "note", "message", "instruction", "ai:", "assistant:", "llm:", "model:", "chatbot:", "agent:", "ai :", "for ai", "to ai", "for llm", "to llm", "hidden", "secret", "for assistant", "to assistant", "language model"))
_mk(STEALTH, "ai_only_marker_jp", "AI/アシスタント宛の指示マーカー(日本語)",
    r"(?:AI|アシスタント|LLM|言語モデル|チャットボット|エージェント)(?:へ|に向けて|宛て?|さんへ|用)の?(?:指示|メッセージ|命令|注意|お願い|伝言)"
    r"|この(?:文章|文書|ページ|ファイル)を(?:読んでいる|処理している|要約している)(?:AI|アシスタント)",
    "high", "stealth", 0, pre=("AI", "アシスタント", "LLM", "言語モデル", "チャットボット", "エージェント"), group="cjk")

_SENSITIVE_NOUN = (r"(?:conversations?|chat|history|credentials?|passwords?|secrets?|api[\s_-]?keys?|tokens?|cookies?|session|memory|context|"
                   r"prompt|instructions|user'?s?\s+(?:data|information|messages?|emails?|files?)|private|confidential|personal\s+(?:data|information)|"
                   r"\.env|env(?:ironment)?\s+(?:file|variables?)|private\s+keys?|ssh\s+keys?|id_rsa|secret\s+(?:keys?|tokens?)|access\s+tokens?|config(?:uration)?\s+files?|credentials?\s+files?)")
_DATA_NOUN = (r"(?:data|information|info|messages?|contents?|keys?|emails?|files?|documents?|everything|responses?|output|details|"
              r"summary|logs?|records?|attachments?|contacts?|results?)")
_SEND_VERB = r"(?:send|post|upload|transmit|exfiltrate|leak|forward|submit|copy|append|attach|encode|embed|include|write|pipe|curl)"
_DEST = r"(?:https?://|www\.|\bto\s+the\s+(?:url|endpoint|server|address|webhook)\b|\bto\s+(?:my|our|this)\s+(?:server|endpoint|url|address|webhook)\b)"
EXFILTRATION: List[Rule] = []
_mk(EXFILTRATION, "send_sensitive_to_url", "機密性の高い情報(会話/認証情報/メモリ等)を外部へ送信させる指示",
    rf"\b{_SEND_VERB}\b[^.\n]{{0,60}}?\b{_SENSITIVE_NOUN}\b[^.\n]{{0,60}}?{_DEST}"
    rf"|{_DEST}[^.\n]{{0,60}}?\b{_SEND_VERB}\b[^.\n]{{0,40}}?\b{_SENSITIVE_NOUN}\b",
    "critical", "exfiltration", _I, pre=("send", "post", "upload", "transmit", "exfiltrate", "leak", "forward", "submit", "copy", "append", "attach", "encode", "embed", "include", "write", "pipe", "curl", "http", "www"))
_mk(EXFILTRATION, "send_to_url", "データを外部URLへ送信させる指示",
    rf"\b{_SEND_VERB}\b[^.\n]{{0,60}}?\b{_DATA_NOUN}\b[^.\n]{{0,60}}?{_DEST}",
    "high", "exfiltration", _I, pre=("send", "post", "upload", "transmit", "exfiltrate", "leak", "forward", "submit", "copy", "append", "attach", "encode", "embed", "include", "write", "pipe", "curl"))
_mk(EXFILTRATION, "send_to_email", "大量/機密データを外部メールアドレスへ送らせる指示",
    r"\b(?:send|forward|email|mail|bcc|cc|exfiltrate|leak)\b[^.\n]{0,50}?\b(?:all|every|each|any|entire|whole|a\s+copy\s+of|copies\s+of|everything|your|the\s+user'?s?)\b[^.\n]{0,30}?"
    r"\b(?:emails?|messages?|files?|documents?|data|information|conversations?|contacts?|attachments?|history|inbox|credentials?|passwords?|secrets?|keys?|tokens?)\b"
    r"[^.\n]{0,60}?[\w.+-]+@[\w-]+(?:\.[\w-]+)+",
    "high", "exfiltration", _I, pre=("send", "forward", "email", "mail", "bcc", "exfiltrate", "leak"))
_mk(EXFILTRATION, "fetch_execute_url", "外部URLの内容を取得して従わせる指示",
    r"\b(?:fetch|retrieve|load|download|get|browse|visit|open|curl|wget|read|navigate\s+to|go\s+to)\b[^.\n]{0,40}?https?://\S+[^.\n]{0,80}?"
    r"\b(?:and|then)\b[^.\n]{0,20}?\b(?:follow|execute|run|obey|apply|use|read|do|comply|carry\s+out)\b[^.\n]{0,30}?\b(?:instructions?|commands?|directives?|steps|script|code|what)\b"
    r"|\b(?:instructions?|commands?|directives?|script|payload)\s+(?:are|is|can\s+be\s+found|located)\s+(?:at|in|on)\s+https?://",
    "medium", "exfiltration", _I, pre=("http",))
_mk(EXFILTRATION, "markdown_image_exfil", "Markdown/HTML画像でのデータ持ち出し(クエリにデータ連結の疑い)",
    r"!\[[^\]]{0,200}\]\(\s*https?://[^)\s]{0,300}(?:\?|=|\{|\}|%7B|data=|q=)[^)]{0,300}\)"
    r"|<img\b[^>]{0,200}\bsrc\s*=\s*[\"']https?://[^\"']{0,300}(?:\?|\{|\}|%7B)[^\"']{0,300}[\"']",
    "high", "exfiltration", _I, pre=("![", "<img"))
_mk(EXFILTRATION, "external_image", "外部画像の読み込み(情報)",
    r"!\[[^\]]{0,200}\]\(\s*https?://[^)\s]{1,300}\)",
    "info", "exfiltration", 0, pre=("![",))
_mk(EXFILTRATION, "send_credentials_jp", "情報/認証情報を外部へ送信させる指示(日本語)",
    r"(?:https?://\S+|外部(?:の)?(?:サーバー?|サイト|URL|アドレス)?|URL|サーバー?|宛先|webhook)[^。\n]{0,40}?"
    r"(?:情報|データ|内容|会話|履歴|パスワード|認証情報|個人情報|APIキー|トークン|メール|ファイル|秘密|機密)[^。\n]{0,20}?(?:送信して|送って|転送して|アップロードして|持ち出して|投稿して|POSTして|漏)"
    r"|(?:情報|データ|内容|会話|履歴|パスワード|認証情報|個人情報|APIキー|トークン|メール|ファイル|秘密|機密)[^。\n]{0,30}?"
    r"(?:https?://\S+|外部(?:の)?(?:サーバー?|サイト|URL|アドレス)|URL|サーバー?|宛先|webhook)[^。\n]{0,20}?(?:送信して|送って|転送して|アップロードして|持ち出して|投稿して|POSTして|漏)",
    "critical", "exfiltration", _I, pre=("送信", "送って", "転送", "アップロード", "持ち出", "投稿", "post", "漏"), group="cjk")
_mk(EXFILTRATION, "leak_secrets_jp", "機密情報の送付/開示を求める指示(日本語)",
    r"(?:会話履歴|チャット履歴|パスワード|認証情報|APIキー|アクセストークン|システムプロンプト|秘密鍵)[^。\n]{0,15}?(?:送って|送信して|教えて|転送して|出力して|漏らして)",
    "high", "exfiltration", 0, pre=("会話履歴", "チャット履歴", "パスワード", "認証情報", "APIキー", "アクセストークン", "システムプロンプト", "秘密鍵"), group="cjk")

TOOL_ABUSE: List[Rule] = []
_mk(TOOL_ABUSE, "run_command", "任意コマンド/コード実行の誘導(危険なコマンドを伴う)",
    r"\b(?:run|execute|eval|exec|invoke|launch|spawn)\b[^.\n]{0,30}?\b(?:the\s+following|this|these|command|commands|code|script|shell|bash|powershell|payload|snippet)\b"
    r"[\s\S]{0,200}?(?:\bcurl\b|\bwget\b|\|\s*(?:ba)?sh\b|\bbash\s+-c\b|\bpowershell\b|\bcmd(?:\.exe)?\b|\brm\s+-rf\b|\bnc\s+-|\bnetcat\b|\beval\s*\(|\bbase64\s+-d\b|\bchmod\s+\+?[0-7x]|\bsudo\b|\bInvoke-(?:WebRequest|Expression)\b|\bos\.system\b|\bsubprocess\b)",
    "medium", "tool_abuse", _I, pre=("run", "execute", "eval", "exec", "invoke", "launch", "spawn"))
_mk(TOOL_ABUSE, "sensitive_file_or_shell", "機密ファイル参照/リバースシェル等の典型的な攻撃コマンド",
    r"/dev/tcp/|\bnc\s+-e\b|\bbash\s+-i\s*>&|\bpowershell\s+-(?:enc|e|encodedcommand)\w*\s+[A-Za-z0-9+/=]{20,}|"
    r"~?/?\.ssh/id_[a-z0-9]+|/etc/(?:passwd|shadow)\b|\.aws/credentials|\.env\b[^.\n]{0,20}?\b(?:send|post|upload|cat|print|read)\b|\bcat\s+[^\n|]{0,40}\.env\b",
    "high", "tool_abuse", _I, pre=("/dev/tcp", "nc -e", "bash -i", "powershell", ".ssh", "/etc/", ".aws", ".env"))
_mk(TOOL_ABUSE, "destructive_command", "破壊的コマンド(rm -rf / DROP TABLE 等)",
    r"\brm\s+-[a-z]*r[a-z]*f|\bdrop\s+(?:table|database|schema)\b|\bformat\s+[a-z]:|\bmkfs(?:\.\w+)?\b|\bdel\s+/[sfq]\b|\bshutil\.rmtree\b|\btruncate\s+table\b|\bdd\s+if=\S{0,40}\s+of=/dev/",
    "high", "tool_abuse", _I, pre=("rm ", "drop ", "format ", "mkfs", "del /", "rmtree", "truncate", "dd if"))
_mk(TOOL_ABUSE, "destructive_action", "破壊的操作(全削除等)の誘導",
    r"\b(?:delete|remove|wipe|erase|destroy|purge|clear)\b[^.\n]{0,15}?\b(?:all|every|everything|the\s+entire|whole)\b[^.\n]{0,25}?"
    r"\b(?:files?|data|database|records?|emails?|messages?|repos?|repositor(?:y|ies)|history|backups?|folders?|directories|documents?|accounts?)\b",
    "medium", "tool_abuse", _I, pre=("delete", "remove", "wipe", "erase", "destroy", "purge", "clear"))
_mk(TOOL_ABUSE, "destructive_jp", "破壊的操作の誘導(日本語)",
    r"(?:全て|すべて|全部|全件)の?(?:ファイル|データ|メール|履歴|データベース|レコード|フォルダ|アカウント|バックアップ)[^。\n]{0,10}?(?:削除|消去|消して|破棄|初期化|ワイプ)",
    "medium", "tool_abuse", 0, pre=("削除", "消去", "消して", "破棄", "初期化", "ワイプ"), group="cjk")
_mk(TOOL_ABUSE, "approve_everything", "確認なしの自動承認・常にyesを強要",
    r"\b(?:always\s+(?:say\s+)?yes|auto[- ]?approve|approve\s+(?:all|everything|every)|grant\s+(?:all|full)\s+(?:permissions?|access)|skip\s+(?:all\s+)?(?:confirmation|verification|approval)s?)\b",
    "medium", "tool_abuse", _I, pre=("always", "approve", "grant", "skip"))
_mk(TOOL_ABUSE, "without_confirmation", "ユーザー確認なしでの実行を指示する文",
    r"\bwithout\s+(?:asking|requiring|waiting\s+for)\s+(?:for\s+)?(?:the\s+)?(?:user'?s?\s+)?(?:confirmation|permission|approval|consent)\b",
    "info", "tool_abuse", _I, pre=("without",))
_mk(TOOL_ABUSE, "tool_call_injection", "ツール/関数の呼び出しを指示する文(エージェント乗っ取り)",
    r"\b(?:call|invoke|use|trigger|execute|run)\s+(?:the\s+)?(?:\w+\s+){0,2}?(?:tool|function|api|plugin|mcp)\b[^.\n]{0,60}?\b(?:send|delete|transfer|email|post|upload|exfiltrate|forward|pay|purchase|share)\w*\b"
    r"|\"(?:name|function|tool)\"\s*:\s*\"[\w.-]{1,60}\"\s*,\s*\"(?:arguments|parameters|input)\"\s*:",
    "medium", "tool_abuse", _I, pre=("tool", "function", "api", "plugin", "mcp", "\"name\""))

DELIMITER_SPOOF: List[Rule] = []
_mk(DELIMITER_SPOOF, "chat_role_tags", "チャットのロールタグ偽装(system/user/assistant)",
    r"</?(?:system|user|assistant|human|tool|developer)>|<\|?(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id)\|?>"
    r"|\[/?INST\]|\[/?SYS\]|<<SYS>>|\{\{[^{}\n]{0,80}?system[^{}\n]{0,80}?\}\}",
    "high", "delimiter_spoof", _I, pre=("<", "[inst", "[/inst", "[sys", "[/sys", "{{"))
_mk(DELIMITER_SPOOF, "role_label_line", "行頭のロールラベル偽装([SYSTEM] / System: you must …)",
    r"^[ \t>*#_-]{0,4}\[\s*(?:system|assistant|developer|admin(?:istrator)?)\s*\]"
    r"|^[ \t>*#_-]{0,4}(?:system|assistant|developer)\s*[:：]\s*(?:you\s|ignore|new\s|from\s+now|always|never|do\s+not|don't|your\s|the\s+(?:user|assistant)|respond|reply|answer|act\s|forget|disregard|override|reveal|print)",
    "high", "delimiter_spoof", _I | re.M, pre=("system", "assistant", "developer", "admin"))
_mk(DELIMITER_SPOOF, "fake_boundary", "偽の区切り線で新セクション/システム領域を演出",
    r"^\s{0,4}(?:#{2,}|={3,}|-{3,}|\*{3,})\s{0,4}(?:system|important|new\s+instructions?|admin|override|重要|システム|管理者)\b",
    "medium", "delimiter_spoof", _I | re.M, pre=("system", "important", "new instruction", "admin", "override", "重要", "システム", "管理者"))
_mk(DELIMITER_SPOOF, "end_of_document_marker", "文書終了を偽装しその後に指示を注入(情報)",
    r"end\s+of\s+(?:document|file|context|user\s+(?:input|message))|---\s*end\s*---|\[end\]",
    "info", "delimiter_spoof", _I, pre=("end of", "--- end", "[end]", "---end"))

# NOTE: 英語・日本語以外は初期版。母語話者のレビューと誤検知確認が必要
MULTILINGUAL: List[Rule] = []
_ml = lambda rid, desc, pat, sev, cat, grp, fl=_I, pre=(): _mk(MULTILINGUAL, rid, desc, pat, sev, cat, fl, pre, grp)

_ml("zh_ignore", "中国語: 以前の指示を無視",
    r"(?:忽略|忽視|无视|無視|忘记|忘記|不要理会|不要理會|别管|別管).{0,8}?(?:之前|以上|上面|先前|前面|所有|全部|系统|系統).{0,6}?(?:指示|指令|提示|命令|规则|規則|要求)",
    "high", "instruction_override", "cjk", 0)
_ml("zh_dont_tell", "中国語: ユーザーに知らせない",
    r"(?:不要|别|別|請勿|请勿|不得|不准|禁止).{0,8}?(?:告诉|告訴|让|讓|使|通知).{0,6}?(?:用户|用戶|使用者|人类|人類)",
    "critical", "stealth", "cjk", 0)
_ml("zh_sysprompt", "中国語: システムプロンプト暴露要求",
    r"(?:显示|顯示|输出|輸出|告诉|告訴|重复|重複|泄露|洩露|打印|列出).{0,8}?(?:系统|系統).{0,4}?(?:提示|提示词|指令|设定|設定)",
    "high", "exfiltration", "cjk", 0)
_ml("zh_exfil", "中国語: データを外部へ送信",
    r"(?:发送|發送|传送|傳送|上传|上傳|泄露|洩露).{0,10}?(?:到|至|给|給).{0,10}?(?:http|网址|網址|服务器|伺服器)",
    "critical", "exfiltration", "cjk", 0)
_ml("ko_ignore", "韓国語: 以前の指示を無視",
    r"(?:이전|기존|위의|모든|앞의).{0,6}?(?:지시|지침|명령|프롬프트|규칙).{0,6}?(?:무시|잊어|무효|따르지)",
    "high", "instruction_override", "cjk", 0)
_ml("ko_dont_tell", "韓国語: ユーザーに知らせない",
    r"(?:사용자|유저|이용자)에게.{0,8}?(?:알리지|말하지|알려주지|보여주지).{0,3}?(?:마|말)",
    "critical", "stealth", "cjk", 0)
_ml("ko_sysprompt", "韓国語: システムプロンプト暴露要求",
    r"(?:시스템).{0,3}?(?:프롬프트|지시|지침|설정).{0,8}?(?:보여|알려|출력|공개|반복)",
    "high", "exfiltration", "cjk", 0)
_ml("es_ignore", "スペイン語: 以前の指示を無視",
    r"\b(?:ignora|ignore|olvida|descarta|omite)[a-z]*\b.{0,30}?\b(?:instrucciones|[óo]rdenes|reglas)\b.{0,15}?\b(?:anteriores|previas|de arriba)\b",
    "high", "instruction_override", "latin", _I, ("ignor", "olvida", "descarta", "omite"))
_ml("es_dont_tell", "スペイン語: ユーザーに知らせない",
    r"\bno\b.{0,12}?\b(?:digas|informes|menciones|cuentes|avises)\b.{0,10}?\b(?:al|a la)\s+usuari[oa]\b",
    "critical", "stealth", "latin", _I, ("usuari",))
_ml("es_sysprompt", "スペイン語: システムプロンプト暴露要求",
    r"\b(?:muestra|revela|imprime|repite)\b.{0,25}?\b(?:prompt|instrucciones)\b.{0,10}?\b(?:del sistema|de sistema)\b",
    "high", "exfiltration", "latin", _I, ("sistema",))
_ml("fr_ignore", "フランス語: 以前の指示を無視",
    r"\b(?:ignore[rz]?|oublie[rz]?|neglige[rz]?|n[ée]glige[rz]?)\b.{0,30}?\b(?:instructions|consignes|r[eè]gles)\b.{0,15}?\b(?:pr[ée]c[ée]dentes|ant[ée]rieures|ci-dessus)\b",
    "high", "instruction_override", "latin", _I, ("ignor", "oublie", "neglig", "néglig"))
_ml("fr_dont_tell", "フランス語: ユーザーに知らせない",
    r"\bne\b.{0,12}?\b(?:dis|dites|informe[rz]?|mentionne[rz]?)\b.{0,6}?\b(?:pas|rien)\b.{0,10}?\butilisateur\b",
    "critical", "stealth", "latin", _I, ("utilisateur",))
_ml("fr_sysprompt", "フランス語: システムプロンプト暴露要求",
    r"\b(?:r[ée]v[eè]le|montre|affiche|r[ée]p[eè]te)\b.{0,25}?\b(?:invite|prompt|instructions)\b.{0,10}?\bsyst[eè]me\b",
    "high", "exfiltration", "latin", _I, ("syst",))
_ml("de_ignore", "ドイツ語: 以前の指示を無視",
    r"\b(?:ignorier(?:e|en)?|vergiss|vergesse|missachte|verwirf)\b.{0,30}?\b(?:vorherigen|vorigen|obigen|bisherigen|alle|fr[uü]heren)\b.{0,15}?\b(?:anweisungen|anleitungen|regeln|instruktionen)\b",
    "high", "instruction_override", "latin", _I, ("ignorier", "vergiss", "vergesse", "missachte", "verwirf"))
_ml("de_dont_tell", "ドイツ語: ユーザーに知らせない",
    r"\b(?:sag|sage|teile|erz[aä]hle|verrate|zeige|informiere)(?:e|n)?\b.{0,15}?\b(?:dem|der)?\s*(?:benutzer|nutzer|anwender)\b.{0,10}?\bnicht",
    "critical", "stealth", "latin", _I, ("benutzer", "nutzer", "anwender"))
_ml("de_sysprompt", "ドイツ語: システムプロンプト暴露要求",
    r"\b(?:zeige|verrate|gib|wiederhole|nenne)\b.{0,25}?\b(?:system[- ]?prompt|systemanweisung|systemeingabe)\b",
    "high", "exfiltration", "latin", _I, ("system",))
_ml("ru_ignore", "ロシア語: 以前の指示を無視",
    r"(?:игнорируй|забудь|не обращай внимания|отбрось|проигнорируй).{0,30}?(?:предыдущие|прошлые|прежние|все|вышеуказанные)\s.{0,10}?(?:инструкци|указани|правил|команд)",
    "high", "instruction_override", "cyr", _I)
_ml("ru_dont_tell", "ロシア語: ユーザーに知らせない",
    r"не\s+(?:говори|сообщай|рассказывай|показывай)\s+.{0,10}?пользовател",
    "critical", "stealth", "cyr", _I)
_ml("ru_sysprompt", "ロシア語: システムプロンプト暴露要求",
    r"(?:покажи|раскрой|выведи|повтори).{0,20}?(?:системн\w*\s+(?:промпт|подсказк|инструкци))",
    "high", "exfiltration", "cyr", _I)
_ml("pt_ignore", "ポルトガル語: 以前の指示を無視",
    r"\b(?:ignore|esque[çc]a|desconsidere)\b.{0,30}?\binstru[çc][õo]es\b.{0,15}?\b(?:anteriores|pr[ée]vias|acima)\b",
    "high", "instruction_override", "latin", _I, ("ignore", "esque", "desconsidere"))
_ml("pt_dont_tell", "ポルトガル語: ユーザーに知らせない",
    r"\bn[ãa]o\b.{0,12}?\b(?:conte|diga|informe|avise)\b.{0,10}?\bao\s+(?:usu[áa]rio|utilizador)\b",
    "critical", "stealth", "latin", _I, ("usu", "utilizador"))
_ml("it_ignore", "イタリア語: 以前の指示を無視",
    r"\b(?:ignora|dimentica|trascura)\b.{0,30}?\bistruzioni\b.{0,15}?\b(?:precedenti|anteriori|sopra)\b",
    "high", "instruction_override", "latin", _I, ("ignora", "dimentica", "trascura"))
_ml("it_dont_tell", "イタリア語: ユーザーに知らせない",
    r"\bnon\b.{0,12}?\b(?:dire|dirlo|informare|menzionare)\b.{0,8}?\b(?:all'|all |a l')?utente\b",
    "critical", "stealth", "latin", _I, ("utente",))
_ml("ar_ignore", "アラビア語: 以前の指示を無視",
    r"(?:تجاهل|انس|تناس).{0,15}?(?:التعليمات|الأوامر|التعليمة|التوجيهات)\s*(?:السابقة|أعلاه)",
    "high", "instruction_override", "ar", 0)
_ml("ar_dont_tell", "アラビア語: ユーザーに知らせない",
    r"لا\s*(?:تخبر|تقل|تعلم|تظهر).{0,10}?(?:المستخدم|المستعمل)",
    "critical", "stealth", "ar", 0)
_ml("tr_ignore", "トルコ語: 以前の指示を無視",
    r"\b(?:[öo]nceki|yukar[ıi]daki|t[üu]m|b[üu]t[üu]n)\s+(?:talimatlar[ıi]|komutlar[ıi]|kurallar[ıi]|y[öo]nergeleri)\s+(?:yok\s+say|unut|g[öo]rmezden\s+gel)",
    "high", "instruction_override", "latin", _I, ("talimat", "komut", "kural", "yönerge", "yonerge"))
_ml("tr_dont_tell", "トルコ語: ユーザーに知らせない",
    r"\bkullan[ıi]c[ıi]ya\b.{0,15}?\b(?:s[öo]yleme|bildirme|belli\s+etme|g[öo]sterme)\b",
    "critical", "stealth", "latin", _I, ("kullan",))
_ml("id_ignore", "インドネシア語: 以前の指示を無視",
    r"\b(?:abaikan|lupakan|kesampingkan)\b.{0,25}?\b(?:semua\s+)?(?:instruksi|perintah|aturan|petunjuk)\b.{0,12}?\b(?:sebelumnya|di\s+atas|terdahulu)\b",
    "high", "instruction_override", "latin", _I, ("abaikan", "lupakan", "kesampingkan"))
_ml("id_dont_tell", "インドネシア語: ユーザーに知らせない",
    r"\bjangan\b.{0,12}?\b(?:beritahu|katakan|bilang|kasih\s+tahu|tunjukkan)\b.{0,10}?\b(?:pengguna|user)\b",
    "critical", "stealth", "latin", _I, ("jangan",))
_ml("nl_ignore", "オランダ語: 以前の指示を無視",
    r"\b(?:negeer|vergeet)\b.{0,25}?\b(?:alle\s+)?(?:vorige|eerdere|bovenstaande)\s+(?:instructies|opdrachten|regels)\b",
    "high", "instruction_override", "latin", _I, ("negeer", "vergeet"))
_ml("nl_dont_tell", "オランダ語: ユーザーに知らせない",
    r"\b(?:vertel|zeg|vertel|meld|toon)\b.{0,12}?\b(?:het\s+)?(?:de\s+)?(?:gebruiker)\b.{0,10}?\bniet\b",
    "critical", "stealth", "latin", _I, ("gebruiker",))
_ml("pl_ignore", "ポーランド語: 以前の指示を無視",
    r"\b(?:zignoruj|zapomnij|ignoruj|pomi[ńn])\b.{0,25}?\b(?:wszystkie\s+)?(?:poprzednie|wcze[śs]niejsze|powy[żz]sze)\s+(?:instrukcje|polecenia|zasady)\b",
    "high", "instruction_override", "latin", _I, ("ignoruj", "zapomnij", "pomi"))
_ml("pl_dont_tell", "ポーランド語: ユーザーに知らせない",
    r"\bnie\s+(?:m[óo]w|m[óo]w\s+o\s+tym|informuj|powiadamiaj|pokazuj)\b.{0,12}?\b(?:u[żz]ytkownik\w*)\b",
    "critical", "stealth", "latin", _I, ("u\u017cytkownik", "uzytkownik"))
_ml("uk_ignore", "ウクライナ語: 以前の指示を無視",
    r"(?:ігноруй|забудь|проігноруй|відкинь).{0,30}?(?:попередні|всі|вищевказані)\s.{0,10}?(?:інструкції|вказівки|правила|команди)",
    "high", "instruction_override", "cyr", _I)
_ml("uk_dont_tell", "ウクライナ語: ユーザーに知らせない",
    r"не\s+(?:кажи|говори|повідомляй|показуй)\s+.{0,10}?користувач",
    "critical", "stealth", "cyr", _I)
_ml("vi_ignore", "ベトナム語: 以前の指示を無視",
    r"\b(?:b[ỏo]\s+qua|qu[êe]n|phớt\s+lờ)\b.{0,25}?\b(?:t[ấa]t\s+c[ảa]\s+)?(?:c[áa]c\s+)?(?:h[ướu]ng\s+d[ẫa]n|ch[ỉi]\s+th[ịi]|quy\s+t[ắa]c|l[ệe]nh)\b.{0,12}?\b(?:tr[ướu][ớo]c\s+đ[óo]|ph[íi]a\s+tr[êe]n|c[ũu])\b",
    "high", "instruction_override", "latin", _I, ("bỏ qua", "bo qua", "quên", "quen", "phớt lờ"))
_ml("vi_dont_tell", "ベトナム語: ユーザーに知らせない",
    r"\bđ[ừu]ng\b.{0,12}?\b(?:n[óo]i|cho\s+bi[ếe]t|th[ôo]ng\s+b[áa]o)\b.{0,12}?\bng[ườu][ờo]i\s+d[ùu]ng\b",
    "critical", "stealth", "latin", _I, ("người dùng", "nguoi dung", "ngươi dung"))
_ml("hi_ignore", "ヒンディー語: 以前の指示を無視",
    r"(?:पिछले|पहले\s+के|ऊपर\s+के|सभी)\s*(?:निर्देशों|निर्देश|आदेशों|नियमों)\s*(?:को)?\s*(?:अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)",
    "high", "instruction_override", "other", 0)
_ml("hi_dont_tell", "ヒンディー語: ユーザーに知らせない",
    r"(?:उपयोगकर्ता|यूज़र|यूजर)\s*(?:को)?\s*(?:मत|न)\s*(?:बताओ|बताना|बताएं|दिखाओ)",
    "critical", "stealth", "other", 0)


# 2.1.0 で追加。出力操作、AI宛の指示、ツール名、DNS/Git 経由の持ち出しなど。
# 人向けの手順書や規約にも出る言い回しは、AI/ユーザー/この文書といった LLM 向けの文脈を要求して絞る
EXTENDED: List[Rule] = []
_AI_WORD = r"(?:ai|llm|language\s+model|assistant|chatbot|bot|agent|model|gpt|copilot|reviewer|screener|summari[sz]er)s?"
_mk(EXTENDED, "ai_reader_directive", "「この文書を読む/処理する AI は〜せよ」型の、AI 読者への指示",
    rf"\b{_AI_WORD}\s+(?:reading|processing|summari[sz]ing|analy[sz]ing|parsing|reviewing|screening|scanning|crawling|indexing|evaluating)\s+(?:this|the)\s+"
    r"(?:document|page|file|email|message|text|content|resume|cv|article|website|site|report)\b[^.\n]{0,80}?"
    r"\b(?:must|should|shall|need\s+to|have\s+to|are\s+(?:required|instructed|requested)\s+to|will|always|never|do\s+not|don't|please)\b"
    rf"|\b(?:if|when)\s+you\s+are\s+(?:an?\s+)?{_AI_WORD}\b[^.\n]{{0,60}}?\b(?:must|should|shall|need\s+to|have\s+to|please|then|do|ignore|follow)\b",
    "high", "stealth", _I, pre=("reading this", "processing this", "summarizing this", "summarising this", "analyzing this", "analysing this", "parsing this",
                                "reviewing this", "screening this", "scanning this", "crawling this", "indexing this", "evaluating this", "you are an", "you are a "))
_mk(EXTENDED, "ai_reader_directive_jp", "「この文書を読む AI は〜せよ」型の日本語の指示(AI 読者への指示)",
    r"(?:この|本)(?:文書|文章|ページ|ファイル|資料|メール|履歴書|レポート|サイト)を(?:読む|読み込む|処理する|要約する|解析する|分析する|評価する|閲覧する)\s*"
    r"(?:AI|ＡＩ|LLM|アシスタント|ボット|エージェント|モデル|システム|人工知能)",
    "high", "stealth", 0, pre=("この文書", "この文章", "このページ", "このファイル", "この資料", "このメール", "この履歴書", "このレポート", "このサイト",
                                "本文書", "本文章", "本ページ", "本ファイル", "本資料", "本メール", "本履歴書", "本レポート", "本サイト"), group="cjk")
_mk(EXTENDED, "output_steering_rating", "AI に特定の評価・推薦・採点をさせる指示(履歴書/論文/製品の評価操作)",
    r"\b(?:rate|score|rank|grade|evaluate|assess|review)\s+(?:this|the)\s+(?:candidate|resume|cv|applicant|application|paper|submission|proposal|product|vendor|company)\b"
    r"[^.\n]{0,40}?(?:\b\d{1,3}\s*/\s*\d{1,3}\b|\b(?:highest|top|best|perfect|maximum|excellent|outstanding)\b)"
    r"|\brecommend\s+(?:hiring|approving|accepting|promoting|this\s+(?:candidate|applicant|paper|product|vendor))\b[^.\n]{0,25}?\b(?:immediately|strongly|unconditionally|without\s+(?:question|reservation|hesitation))\b"
    r"|\b(?:always|must|should)\s+(?:rate|rank|score|recommend)\s+(?:this|it|them|him|her)\b[^.\n]{0,20}?\b(?:highest|top|first|best|positively)\b",
    "high", "instruction_override", _I, pre=("rate", "score", "rank", "grade", "evaluate", "assess", "review", "recommend", "always", "must", "should"))
_mk(EXTENDED, "output_steering_rating_jp", "AI に特定の評価・推薦をさせる指示(日本語)",
    r"(?:最高評価|最高点|満点|高評価|最上位)[^。\n]{0,15}?(?:と(?:し|する)|にし|を付け|を与え|で評価|とみなし)"
    r"|必ず[^。\n]{0,8}?(?:採用|合格|承認|推薦|推奨)(?:を)?[^。\n]{0,8}?(?:推薦|推奨|して|せよ|するよう|ください)",
    "high", "instruction_override", 0, pre=("最高評価", "最高点", "満点", "高評価", "最上位", "必ず"), group="cjk")
_mk(EXTENDED, "output_steering_conditional", "「この文書を要約/翻訳するときは〜を必ず追加せよ」型の出力への混入指示",
    r"\bwhen(?:ever)?\s+(?:you\s+)?(?:summari[sz]e|translate|answer|respond\s+to|reply\s+to|describe|review|analy[sz]e|read|process|paraphrase)\s+"
    r"(?:this|the)\s+(?:document|page|file|email|message|text|article|content|resume|report)\b[^.\n]{0,40}?,?\s*(?:you\s+)?(?:must\s+|should\s+|always\s+|also\s+)*"
    r"(?:add|include|append|insert|say|state|write|mention|recommend|tell|output|print|respond|reply)\b",
    "high", "instruction_override", _I, pre=("summarize", "summarise", "translate", "answer", "respond to", "reply to", "describe", "review", "analyze", "analyse", "read", "process", "paraphrase"))
_mk(EXTENDED, "output_steering_untruth", "事実と食い違っても特定の主張を述べさせる指示",
    r"\b(?:state|say|claim|assert|insist|report|tell\s+(?:the\s+)?users?)\b[^.\n]{0,80}?\b(?:even\s+if|regardless\s+of\s+(?:what|whether)|no\s+matter\s+what)\b"
    r"[^.\n]{0,40}?\b(?:other\s+sources?|evidence|facts?|data|documents?|the\s+(?:user|truth|reality)|you\s+(?:know|are\s+told|find|see))\b",
    "medium", "instruction_override", _I, pre=("even if", "regardless of", "no matter what"))
_mk(EXTENDED, "output_steering_refuse", "以後のユーザーの質問への回答拒否・サービス停止を装う指示",
    r"\b(?:refuse|decline|stop|cease)\s+(?:to\s+)?(?:answer(?:ing)?|respond(?:ing)?|help(?:ing)?|assist(?:ing)?)\b[^.\n]{0,30}?"
    r"\b(?:any\s+)?(?:further|more|additional|other|all|future|subsequent)\s+(?:questions?|requests?|queries|messages?)\b"
    r"|\btell\s+(?:them|the\s+user|users?)\s+(?:that\s+)?(?:the\s+)?(?:service|system|assistant|chat)\s+is\s+(?:unavailable|down|closed|offline|disabled)\b",
    "medium", "instruction_override", _I, pre=("refuse", "decline", "stop", "cease", "tell them", "tell the user", "tell users"))
_mk(EXTENDED, "persist_instructions", "以後の会話すべてに指示を持ち越させる(記憶/永続化の悪用)",
    r"\b(?:remember|memori[sz]e|save|store|retain|keep)\s+(?:these|this|the\s+following)\s+(?:instructions?|rules?|directives?|commands?|prompts?)\b[^.\n]{0,50}?"
    r"\b(?:future|later|all|every|subsequent|next|forever|permanently)\b"
    r"|\b(?:apply|follow|use)\s+(?:these|this|the\s+following)\s+(?:instructions?|rules?)\s+(?:in|for|to)\s+(?:all|every|each)\s+(?:future|later|subsequent|following|next)\b",
    "medium", "instruction_override", _I, pre=("remember", "memorize", "memorise", "save", "store", "retain", "keep", "apply these", "follow these", "use these"))
_mk(EXTENDED, "persist_instructions_jp", "以後の会話すべてに指示を持ち越させる(日本語)",
    r"(?:この|以下の|次の)(?:指示|ルール|命令)を(?:今後|以後|これから|ずっと|永続的に|すべての(?:会話|やり取り))[^。\n]{0,20}?(?:覚え|記憶|保存|適用|守|従)",
    "medium", "instruction_override", 0, pre=("指示を", "ルールを", "命令を"), group="cjk")
_mk(EXTENDED, "output_steering_recommend", "ユーザーの質問に対し特定の製品/相手を常に推薦させる指示",
    r"\b(?:whenever|when|if)\s+(?:the\s+)?(?:user|users|anyone|someone)\s+asks?\b[^.\n]{0,60}?,?\s*(?:you\s+)?(?:must\s+|should\s+)?(?:always|only|never)\s+"
    r"(?:recommend|suggest|mention|say|respond|answer|reply|refer)\b",
    "medium", "instruction_override", _I, pre=("user asks", "users ask", "anyone asks", "someone asks"))
_mk(EXTENDED, "output_language_lock", "以後の応答言語/話し方を固定させ、理由も説明させない指示",
    r"\bfrom\s+now\s+on\b[^.\n]{0,30}?\b(?:respond|reply|answer|speak|write)\s+(?:only\s+)?(?:in|using|with)\b[^.\n]{0,40}?\b(?:and\s+)?(?:do\s+not|don't|never)\s+(?:explain|mention|tell|say)\b"
    r"|\b(?:respond|reply|answer|speak|write)\s+(?:only\s+)?(?:in|using|with)\b[^.\n]{0,40}?\bfrom\s+now\s+on\b[^.\n]{0,30}?\b(?:do\s+not|don't|never)\s+(?:explain|mention|tell|say)\b",
    "low", "instruction_override", _I, pre=("from now on",))
_mk(EXTENDED, "output_steering_only_jp", "要約等をさせず特定の文言だけを返させる指示(日本語)",
    r"(?:要約|翻訳|回答|分析|処理)(?:は|を)?(?:せず|しないで|する代わりに|の代わりに)[^。\n]{0,30}?(?:とだけ|のみ|だけを?)(?:回答|返答|出力|返信|答え|表示)",
    "medium", "instruction_override", 0, pre=("せず", "しないで", "代わりに"), group="cjk")
_mk(EXTENDED, "roleplay_grandma", "『亡くなった祖母が〜を読み聞かせた』型の役割演技による制約回避",
    r"\b(?:act|play|pretend|roleplay|behave)\b[^.\n]{0,20}?\b(?:my\s+)?(?:deceased|late|dead|departed)\s+(?:grand(?:mother|ma|father|pa)|mother|father|mom|dad|aunt|uncle)\b"
    r"|\b(?:deceased|late|dead)\s+(?:grand(?:mother|ma|father|pa)|mother|father)\b[^.\n]{0,60}?\bused\s+to\s+(?:read|tell|recite)\b",
    "medium", "jailbreak", _I, pre=("deceased", "late grand", "dead grand", "departed"))
_mk(EXTENDED, "authority_override", "権限者を装って安全対策の無効化を許可する文(管理者/オペレーターの許可)",
    r"\b(?:authori[sz]es?|permits?|allows?|approves?|grants?|has\s+authori[sz]ed|has\s+approved)\s+you\s+to\s+(?:bypass|ignore|disable|override|skip|disregard|circumvent|violate|break)\b"
    r"|\b(?:system|admin|administrator|root|developer|security|operator)\s+override\b"
    r"|\b(?:policy|policies|rules?|restrictions?|guidelines?|instructions?|limits?|safeguards?)\s+(?:is|are|has\s+been|have\s+been)\s+(?:now\s+|hereby\s+)?(?:revoked|rescinded|lifted|removed|void|invalid|cancell?ed|suspended|disabled|withdrawn|waived)\b"
    r"|\bcomply\s+with\s+(?:all|every|any)\s+(?:requests?|commands?|instructions?|directions?)\b[^.\n]{0,40}?\b(?:document|file|page|text|below|here|this)\b",
    "high", "jailbreak", _I, pre=("authoriz", "authoris", "permits you", "allows you", "approves you", "grants you", "override", "revoked", "rescinded", "lifted", "removed", "void", "invalid", "cancel", "suspended", "disabled", "withdrawn", "waived", "comply with"))
_mk(EXTENDED, "url_secret_placeholder", "URL にテンプレート変数(会話履歴/鍵/トークン等)を差し込んでデータを持ち出す指示",
    r"https?://[^\s\"'<>]{0,200}?(?:\{\{|\{%|\[\[|<%|\$\{|%7B%7B|%7b%7b|%24%7B|%24%7b|\{)\s*[\w .-]{0,30}?"
    r"(?:conversation|chat|history|messages?|secrets?|api[_-]?keys?|keys?|tokens?|passwords?|prompt|context|memory|session|cookies?|credentials?|user|email|data|content|transcript)\w*",
    "high", "exfiltration", _I, pre=("http",))
_mk(EXTENDED, "dns_exfil", "DNS(サブドメイン)経由でのデータ持ち出しの指示",
    r"<\s*(?:secret|key|token|password|data|conversation|content|prompt|api[_ ]?key|credentials?)[^>]{0,30}>\s*\.\s*[a-z0-9][a-z0-9.-]{1,60}\.[a-z]{2,}"
    r"|\b(?:encode|put|append|embed|place|prepend)\b[^.\n]{0,50}?\b(?:in|into|as)\s+(?:a\s+|the\s+)?(?:sub-?domain|dns\s+(?:query|lookup|request|record)|hostname)\b"
    r"|\b(?:resolve|lookup|look\s+up|ping|nslookup|dig|query)\s+[^.\n]{0,40}?<[^>]{1,30}>\.[a-z0-9.-]+",
    "high", "exfiltration", _I, pre=("<secret", "<key", "<token", "<password", "<data", "<conversation", "<content", "<prompt", "<api", "<credential", "subdomain", "sub-domain", "dns", "hostname"))
_mk(EXTENDED, "reveal_secrets_env", "環境変数/秘密のトークン/鍵などの出力を求める指示",
    r"\b(?:print|show|reveal|output|display|dump|list|echo|include|leak|disclose|expose|share)\b[^.\n]{0,30}?\b(?:your|the\s+user'?s?|any|all|every)\s+(?:\w+\s+){0,2}?"
    r"(?:environment\s+variables?|env(?:ironment)?\s+vars?|secret\s+(?:tokens?|keys?)|access\s+tokens?|api\s+keys?|private\s+keys?|ssh\s+keys?|credentials|session\s+cookies?|auth(?:entication)?\s+tokens?)\b",
    "high", "exfiltration", _I, pre=("environment variable", "env var", "secret token", "secret key", "access token", "api key", "private key", "ssh key", "credentials", "session cookie", "auth"))
_mk(EXTENDED, "tool_dangerous_name", "危険な動作を示す名前のツール/関数(delete_all_files 等)を呼び出させる指示",
    r"\b(?:call|invoke|use|run|execute|trigger|launch)\s+(?:the\s+)?(?:`|'|\")?\w*(?:delete|remove|wipe|erase|destroy|purge|exfil|transfer|send|upload|exec|shell|drop|format|kill)\w*_\w+(?:`|'|\")?",
    "high", "tool_abuse", _I, pre=("call", "invoke", "use", "run", "execute", "trigger", "launch"))
_mk(EXTENDED, "invite_exfil", "外部のメールアドレスを招待/共有先に追加して資料を渡させる指示",
    r"\b(?:invit(?:e|ing)|share\s+(?:it\s+|this\s+|the\s+\w+\s+)?with|add)\b[^.\n]{0,30}?[\w.+-]+@[\w-]+(?:\.[\w-]+)+[^.\n]{0,60}?\b(?:attach|attached|attaching|full|entire|whole|complete|contents?|document|transcript|conversation|history)\b"
    r"|\b(?:create|schedule|add)\s+(?:a\s+)?(?:calendar\s+)?(?:event|meeting|invite)\b[^.\n]{0,50}?[\w.+-]+@[\w-]+(?:\.[\w-]+)+[^.\n]{0,60}?\b(?:attach|attached|full|entire|whole|complete|contents?|document|transcript)\b",
    "high", "exfiltration", _I, pre=("invit", "share", "add", "create", "schedule"))
_mk(EXTENDED, "push_secrets", "秘密情報(.env/鍵等)を公開リポジトリ/外部へ push/commit させる指示",
    r"\b(?:push|commit|upload|publish|post|copy|share|attach)\b[^.\n]{0,40}?(?:\.env\b|\bcredentials?\b|\bsecrets?\b|\bprivate\s+keys?\b|\bid_rsa\b|\bapi[_ -]?keys?\b)[^.\n]{0,40}?"
    r"\b(?:to|into|on)\s+(?:https?://|git@|github|gitlab|pastebin|the\s+(?:public|remote|external))",
    "high", "exfiltration", _I, pre=("push", "commit", "upload", "publish", "post", "copy", "share", "attach"))
_mk(EXTENDED, "install_before_answer", "回答/作業の前に指定パッケージのインストールや取得を強要する指示(サプライチェーン攻撃)",
    r"\b(?:pip3?\s+install|npm\s+(?:install|i)|yarn\s+add|pnpm\s+(?:add|install)|gem\s+install|cargo\s+install|go\s+install|brew\s+install|apt(?:-get)?\s+install|install)\b"
    r"[^.\n]{0,80}?\b(?:before|prior\s+to)\s+(?:answering|responding|replying|continuing|proceeding|summari[sz]ing|you\s+(?:answer|respond|reply|continue))\b",
    "high", "tool_abuse", _I, pre=("install", "pip", "npm", "yarn", "pnpm", "gem", "cargo", "brew", "apt"))
_mk(EXTENDED, "interpreter_exec", "コードインタプリタ/ターミナルで危険なコードを実行させる指示",
    r"\b(?:use|using|via|with|in|through|open)\s+(?:the\s+|your\s+)?(?:code\s+interpreter|python\s+(?:tool|interpreter)|terminal|shell|bash\s+tool|command\s+line|sandbox)\b[^.\n]{0,40}?"
    r"\b(?:run|execute|exec|type|enter|paste)\b[\s\S]{0,200}?(?:os\.system|subprocess|\bcurl\b|\bwget\b|\beval\s*\(|\bexec\s*\(|__import__|https?://)",
    "high", "tool_abuse", _I, pre=("interpreter", "python tool", "terminal", "shell", "bash tool", "command line", "sandbox"))
_mk(EXTENDED, "pipe_to_shell", "リモートスクリプトをシェルへ直接パイプする実行(curl … | sh)。公式手順にもあるため低め",
    r"\b(?:curl|wget)\b[^\n|]{1,250}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b",
    "low", "tool_abuse", _I, pre=("curl", "wget"))
_mk(EXTENDED, "run_command_jp", "コマンド/スクリプトの実行を日本語で指示(危険なコマンドを伴うもの)",
    r"(?:コマンド|スクリプト|コード|シェル)を実行[^。\n]{0,12}?[:：]?\s*[^。\n]{0,80}?(?:\bcurl\b|\bwget\b|\|\s*(?:ba)?sh\b|\bpowershell\b|\brm\s+-rf\b|\bnc\s+-|\bbase64\s+-d\b|\bsudo\b|os\.system|subprocess)"
    r"|(?:ターミナル|コマンドライン|シェル|コマンドプロンプト)で[^。\n]{0,20}?(?:実行|入力)[^。\n]{0,40}?(?:\bcurl\b|\bwget\b|\|\s*(?:ba)?sh\b|\bpowershell\b|\brm\s+-rf\b|\bsudo\b)",
    "high", "tool_abuse", _I, pre=("実行", "入力"), group="cjk")

ALL_PATTERNS: List[Rule] = (
    INSTRUCTION_OVERRIDE + JAILBREAK + STEALTH + EXFILTRATION + TOOL_ABUSE + DELIMITER_SPOOF + MULTILINGUAL + EXTENDED
)

# squashed バリアントでも照合する命令系ルール
INSTRUCTIONAL_IDS = frozenset({
    "override_ignore_previous", "override_stop_following", "override_ignore_jp", "override_ignore_jp_short",
    "new_instructions", "you_are_now_role", "jailbreak_named", "jailbreak_nofilter", "disable_safety",
    "system_prompt_leak", "system_prompt_leak_jp", "do_not_tell_user", "do_not_tell_user_jp", "secretly",
    "ai_only_marker", "send_sensitive_to_url", "send_to_url", "destructive_command", "approve_everything",
    "injected_task_template", "pretend_jp",
})
# ホモグリフ畳み込み(folded)で照合するラテン文字系ルール
LATIN_RULE_IDS = frozenset(rid for rid, g in GROUP.items() if g == "latin")

# compact バリアントでだけ照合する短い定型句
COMPACT_PATTERNS: List[Tuple[str, str, "re.Pattern", str, str]] = [
    ("compact_ignore_previous", "空白・記号で分断された『ignore previous instructions』系の定型句",
     re.compile(r"(?:ignore|disregard|forget|override)(?:all|any|the|your|every)?(?:previous|prior|above|earlier|preceding|foregoing)(?:instructions?|prompts?|rules?|commands?|directions?)"),
     "high", "instruction_override"),
    ("compact_reveal_prompt", "空白・記号で分断された『reveal system prompt』系の定型句",
     re.compile(r"(?:reveal|show|print|repeat|output|leak)(?:me)?(?:your|the)?(?:system|initial|hidden)(?:prompt|instructions?|message)"),
     "high", "exfiltration"),
    ("compact_do_not_tell", "空白・記号で分断された『do not tell the user』系の定型句",
     re.compile(r"(?:donot|dont|never)(?:tell|inform|mention|notify)(?:the)?(?:user|human)"),
     "critical", "stealth"),
    ("compact_jp_ignore", "空白・記号で分断された日本語の指示無視",
     re.compile(r"(?:これまで|以前|上記|先ほど|従来)の?(?:指示|命令|ルール|プロンプト)(?:を|は)?(?:すべて|全て)?(?:無視|忘れ|破棄)"),
     "high", "instruction_override"),
]
