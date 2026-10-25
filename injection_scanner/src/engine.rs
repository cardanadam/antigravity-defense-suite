use html_escape::decode_html_entities;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;
use urlencoding::decode;

#[derive(Serialize, Clone, Debug)]
pub struct ScanResult {
    pub is_safe: bool,
    pub risk_score: u8,
    pub threat_level: String,
    pub matches: Vec<(String, f32, String)>, // (Category, Confidence, Snippet)
}

struct CompiledRule {
    category: &'static str,
    weight: u8,
    confidence: f32,
    regex: Regex,
}

struct CompiledEngine {
    rules: Vec<CompiledRule>,
    benign_tech_re: Regex,
    ai_target_re: Regex,
    question_re: Regex,
    negated_prefix_re: Regex,
    b64_re: Regex,
    hex_re: Regex,
    spaced_punct_re: Regex,
    spaced_ws_re: Regex,
    segment_re: Regex,
    leet_token_re: Regex,
}

static GLOBAL_COMPILED: OnceLock<CompiledEngine> = OnceLock::new();

fn get_compiled() -> &'static CompiledEngine {
    GLOBAL_COMPILED.get_or_init(|| {
        let raw_rules: Vec<(&'static str, u8, f32, &'static str)> = vec![
            // =========================================================================
            // 1. DIRECT & PARAPHRASED INSTRUCTION OVERRIDE (EN + TR)
            // =========================================================================
            // EN: Action Verb + Qualifier + Target Noun
            (
                "direct_injection",
                75,
                0.95,
                r"(?is)\b(ignore|disregard|forget|set\s+aside|put\s+aside|drop|abandon|override|bypass|discard|clear|reset|erase|wipe|nullify|cancel|dismiss|skip)\b.{0,55}\b(all|any|every|your|the|previous|prior|earlier|above|initial|original|preceding|existing|current|system|safety|core|built-?in|default)\b.{0,40}\b(instructions?|directives?|rules?|guidelines?|constraints?|programming|guardrails?|prompts?|context|limitations?|restrictions?|boundaries|policies|commands?|orders?|objectives?|roles?|personas?|training)\b",
            ),
            // EN: Direct Verb + AI/System Target Noun
            (
                "direct_injection",
                75,
                0.93,
                r"(?is)\b(ignore|disregard|forget|override|bypass|abandon|nullify|discard|dismiss)\s+(?:the\s+|your\s+|all\s+|any\s+)?(system\s+prompt|system\s+rules?|system\s+instructions?|safety\s+rules?|safety\s+guidelines?|guardrails?|core\s+directives?|ethical\s+constraints?|initial\s+directives?|prior\s+instructions?|previous\s+instructions?|above\s+instructions?)\b",
            ),
            // EN: Target Noun + is/are + negated/voided
            (
                "direct_injection",
                75,
                0.92,
                r"(?is)\b(previous|prior|earlier|initial|original|existing|above|system|safety|all)\s+(instructions?|directives?|rules?|guidelines?|constraints?|restrictions?|guardrails?|policies|prompts?)\b.{0,35}\b(are\s+now\s+|are\s+|is\s+)(deprecated|void|cancelled|canceled|invalid|nullified|suspended|revoked|no\s+longer\s+apply|no\s+longer\s+in\s+effect|no\s+longer\s+valid|overridden|abolished)\b",
            ),
            // EN: Paraphrased context reset & new primary directive
            (
                "direct_injection",
                75,
                0.90,
                r"(?is)\b(adopt\s+this\s+new\s+primary\s+objective|follow\s+only\s+the\s+instructions?\s+below|forget\s+everything\s+(?:you\s+were\s+told|above|before\s+this)|disregard\s+your\s+programming|start\s+from\s+a\s+clean\s+slate|wipe\s+your\s+context\s+memory|from\s+this\s+(?:point|moment)\s+(?:on|onward|forward)\s+only\s+(?:follow|obey|listen\s+to)|do\s+not\s+follow\s+any\s+prior\s+rules?|whatever\s+you\s+were\s+told\s+before.{0,20}(?:forget|ignore)|disregard\s+anything\s+above|ignore\s+everything\s+above|your\s+new\s+primary\s+(?:instruction|directive|task|role)\s+is)\b",
            ),
            // TR: Explicit AI/System/Prompt/Security Target Noun + 2nd-person Imperative Override Verb
            // (Safe morphology: excludes 'unutma/unutmayin', excludes 3rd-person '-se/-sa' and 1st-person past '-dim/-dik')
            (
                "direct_injection",
                75,
                0.95,
                r"(?is)\b(sistem\s+talimat\w*|sistem\s+kural\w*|sistem\s+yonerge\w*|sistem\s+istem\w*|sistem\s+prompt\w*|sistem\s+mesaj\w*|sistem\s+ayar\w*|sistem\s+komut\w*|guvenlik\s+kural\w*|guvenlik\s+kisitlama\w*|guvenlik\s+sinir\w*|guvenlik\s+onlem\w*|guvenlik\s+politik\w*|guvenlik\s+ilke\w*|guvenlik\s+filtre\w*|koruma\s+katman\w*|davranis\s+ilke\w*|etik\s+ilke\w*|etik\s+kural\w*|etik\s+sinir\w*)\b.{0,55}\b(unut(?:un|unuz|malisin|up|arak)?|yok\s*say(?:in|iniz|malisin|ip|arak)?|gormezden\s+gel(?:in|iniz|melisin|ip|erek)?|bir\s+kenara\s+(?:birak(?:in|malisin|ip)?|koy(?:un|malisin)?|at(?:in|malisin)?)|dikkate\s+alma(?:yin|yiniz|dan|malisin)?|aldirma(?:yin|dan)?|onemseme(?:yin|den)?|devre\s+disi\s+birak(?:in|iniz|malisin|ip|arak)?|etkisiz\s+(?:hale\s+getir(?:in|melisin)?|kil(?:in|malisin)?)|askiya\s+al(?:in|malisin)?|pasif\s+(?:yap(?:in|malisin)?|hale\s+getir(?:in)?)|iptal\s+et(?:melisin|체)?|gecersiz\s+(?:kil(?:in|malisin)?|say(?:in|malisin)?)|sil(?:in|melisin|ebilirsin)?|ortadan\s+kaldir(?:in|malisin)?|kaldir(?:in|iniz|malisin)?|kapat(?:in|iniz|malisin)?|bos\s*ver(?:in|melisin)?|terk\s+et(?:melisin)?|atla(?:yin|malisin)?|cigne(?:yin|melisin)?|rafa\s+kaldir(?:in)?|cope\s+at(?:in)?|uyma(?:yin|yiniz|malisin|dan)?|bagli\s+(?:degilsin\w*|kalma(?:yin|dan)?)|disina\s+cik(?:in|malisin)?|sifirla(?:yin|malisin)?|dinleme(?:yin|den)?)\b",
            ),
            // TR: Generic Rule/Instruction Noun WITH an AI/Context/2nd-Person Anchor + 2nd-Person Override Verb
            // Requires anchor (onceki, yukaridaki, bastaki, sana, senin, kendi, tum, butun, hicbir, mevcut, ilk, asistan, yapay zeka)
            // so 3rd-person game/school/Unity sentences ("Unity'de eski kuralları kaldırıp...", "Oyunda oyuncu kuralları çiğnerse...", "Bu dersin kurallarını unutmayın") never trigger!
            (
                "direct_injection",
                75,
                0.95,
                r"(?is)\b(?:(?:onceki|yukaridaki|yukarida\s+\w+|baslangictaki|bastaki|daha\s+once\s+verilen|sana\s+verilen|sana\s+soylenen|sana\s+tanimlanan|senin|kendi|tum|butun|hicbir|mevcut|ilk)\s+(?:tum\s+|butun\s+)?(talimat\w*|kural\w*|yonerge\w*|kisitlama\w*|sinir\w*|yasak\w*|komut\w*|direktif\w*|programlama\w*|on\s*ayar\w*|gorev\w*|rol\w*)|(talimatlar(?:ini|i)|kurallar(?:ini|i)|yonergeler(?:ini|i)|kisitlamalar(?:ini|i))\s+(?:tamamen|hepsini|tumuyle))\b.{0,50}\b(unut(?:un|unuz|malisin|up|arak)?|yok\s*say(?:in|iniz|malisin|ip|arak)?|gormezden\s+gel(?:in|iniz|melisin|ip|erek)?|bir\s+kenara\s+(?:birak(?:in|malisin|ip)?|koy(?:un|malisin)?|at(?:in|malisin)?)|dikkate\s+alma(?:yin|yiniz|dan|malisin)?|aldirma(?:yin|dan)?|onemseme(?:yin|den)?|devre\s+disi\s+birak(?:in|iniz|malisin|ip|arak)?|etkisiz\s+(?:hale\s+getir(?:in|melisin)?|kil(?:in|malisin)?)|askiya\s+al(?:in|malisin)?|iptal\s+et(?:melisin)?|gecersiz\s+(?:kil(?:in|malisin)?|say(?:in|malisin)?)|sil(?:in|melisin)?|ortadan\s+kaldir(?:in|malisin)?|kaldir(?:in|iniz|malisin)?|kapat(?:in|iniz|malisin)?|bos\s*ver(?:in|melisin)?|terk\s+et(?:melisin)?|atla(?:yin|malisin)?|rafa\s+kaldir(?:in)?|cope\s+at(?:in)?|uyma(?:yin|yiniz|malisin|dan)?|bagli\s+(?:degilsin\w*|kalma(?:yin|dan)?)|disina\s+cik(?:in|malisin)?|sifirla(?:yin|malisin)?|dinleme(?:yin|den)?)\b",
            ),
            // TR: Reversed Order (2nd-Person Override Verb + AI/Context-Anchored Target Noun)
            (
                "direct_injection",
                75,
                0.95,
                r"(?is)\b(unut(?:un|malisin)?|yok\s*say(?:in|malisin)?|gormezden\s+gel(?:in|melisin)?|bir\s+kenara\s+(?:birak(?:in|malisin)?|koy(?:un)?)|dikkate\s+alma(?:yin|dan)?|devre\s+disi\s+birak(?:in|malisin)?|iptal\s+et(?:melisin)?|gecersiz\s+(?:kil(?:in)?|say(?:in)?)|bos\s*ver(?:in)?|terk\s+et(?:melisin)?|askiya\s+al(?:in)?|ortadan\s+kaldir(?:in)?|rafa\s+kaldir(?:in)?|cope\s+at(?:in)?)\b.{0,45}\b(?:(?:onceki|yukaridaki|baslangictaki|sana\s+verilen|senin|kendi|tum|butun|sistem|guvenlik)\s+)?(talimatlar\w*|kurallar\w*|yonergeler\w*|kisitlamalar\w*|direktifler\w*|sistem\s+istem\w*|sistem\s+prompt\w*|guvenlik\s+filtre\w*)\b",
            ),
            // TR: General "everything told / above / earlier" + 2nd-person forget/ignore
            (
                "direct_injection",
                75,
                0.93,
                r"(?is)\b((?:sana\s+)?(?:daha\s+once\s+|basta\s+|baslangicta\s+|onceden\s+)?(?:verilen|soylenen|ogretilen|tanimlanan|yazilan|anlatilan|belirtilen)\s+(?:her\s+seyi|tum\s+\w+|butun\s+\w+|ne\s+varsa|bilgileri|metni)|(?:onceki|yukaridaki|basta\s+yazan|yukarida\s+yazan|az\s+once\s+konustugumuz|gecmis)\s+(?:her\s+seyi|soylenen\w*|konusma\w*|baglam\w*|metni|yazilan\w*|anlatilan\w*|komut\w*|bilgileri)|simdiye\s+kadar\s+(?:soylenen\w*|yazilan\w*|verilen\w*|konustuk\w*))\b.{0,40}\b(unut(?:un|malisin|up)?|sil(?:in|melisin)?|birak(?:in|ip)?|yok\s*say(?:in)?|gormezden\s+gel(?:in)?|dikkate\s+alma(?:yin|dan)?|bos\s*ver(?:in)?|sifirla(?:yin)?|gecersiz\w*|atla(?:yin)?)\b",
            ),
            // TR: Role / task / memory reset & exclusive obedience
            (
                "direct_injection",
                75,
                0.92,
                r"(?is)\b(hafizani\s+sifirla\w*|baglami\s+sifirla\w*|yeni\s+bir\s+sayfa\s+ac\w*|artik\s+hicbir\s+kurala\s+bagli\s+degilsin|hicbir\s+kural\s+yokmus\s+gibi|hicbir\s+kurala\s+bagli\s+degilmis\s+gibi|bundan\s+(?:sonra|boyle|itibaren)\s+(?:sadece|yalniz\w*)\s+(?:benim|asagidaki|bu)|su\s+andan\s+itibaren\s+(?:sadece|yalniz\w*|eski\s+gorev\w*\s+birak)|sadece\s+benim\s+dedigimi\s+yap|sadece\s+bana\s+itaat\s+et|artik\s+yeni\s+gorevin\s+(?:bu|su)|yeni\s+(?:ana\s+|birincil\s+|temel\s+|sistem\s+)?(?:talimatin|gorevin|komutun|rolun|hedefin)\s*(?:su|budur|asagidadir|:)|(?:eski|onceki|mevcut|ilk|baslangictaki)\s+(?:gorevini|rolunu|kimligini|kisiligini|talimatlarini)\s+(?:birak\w*|unut(?:un)?|terk\s+et\w*|iptal\s+et\w*|sil\w*|degistir\w*)|kendi\s+kurallarini\s+unut(?:un)?|baska\s+hicbir\s+(?:kurali|talimati)\s+dinleme(?:yin|den)?)\b",
            ),

            // =========================================================================
            // 2. MULTI-STEP TASK SWITCHING ("END OF DOCUMENT / DROP TASK / NEW TASK")
            // =========================================================================
            // EN: Document/Text End Boundary + Task Switch
            (
                "direct_injection",
                80,
                0.94,
                r"(?is)(?:(?:---|===|\*\*\*)\s*(?:end\s+of\s+(?:the\s+)?(?:article|email|text|document|page|data|message|excerpt|input|file|transcript|context)|new\s+task|new\s+instructions?|system\s+instruction\w*)\s*(?:---|===|\*\*\*)?|(?:\b(?:end\s+of\s+(?:the\s+)?(?:document|text|article|email|message|excerpt|input|file|passage|transcript|summary|translation)|(?:the\s+|this\s+)?(?:document|text|article|email|excerpt|passage|input|summary|translation)\s+(?:ends\s+here|is\s+(?:now\s+)?(?:complete|finished|over|done))|that\s+concludes\s+the\s+(?:document|text|article|email|excerpt|summary|input))|</(?:document|text|article|email|context|data|input|message)>).{0,95}\b(?:now|next|instead|ignore|forget|drop|abandon|stop|new\s+(?:task|instruction|directive|objective|role|assignment)|your\s+(?:real|actual|true|next|new)\s+(?:task|job|goal|instruction|objective)|switch\s+to))",
            ),
            // EN: Drop / Abandon / Finish Current Task -> New Task / Real Objective
            (
                "direct_injection",
                75,
                0.93,
                r"(?is)\b(?:(?:stop|drop|abandon|quit|cancel|abort|discontinue|set\s+aside|forget(?:\s+about)?|leave)\b.{0,30}\b(?:current|previous|prior|initial|original|above|assigned|first|summarization|translation|analysis)?\s*(?:task|job|assignment|objective|mission|activity)|(?:the\s+|your\s+)?(?:previous|prior|current|initial|original|above|first)\s+(?:task|job|assignment|objective)\s+is\s+(?:now\s+)?(?:over|done|cancelled|canceled|complete|finished|obsolete))\b.{0,85}\b(new\s+(?:task|job|objective|instruction|directive|mission|assignment)|your\s+(?:new|real|actual|true|next|primary)\s+(?:task|job|objective|instruction|goal|role)|instead\b|now\s+(?:i\s+want\s+you\s+to|you\s+must|you\s+should|do\s+this|follow|answer|tell\s+me|write|output|execute|print|reveal)|switch\s+to\s+(?:a\s+)?new)\b",
            ),
            // TR: Document/Text End Boundary + Task Switch
            (
                "direct_injection",
                80,
                0.94,
                r"(?is)(?:(?:---|===|\*\*\*)\s*(?:makale(?:nin)?\s+sonu|metn?in\s+sonu|belge(?:nin)?\s+sonu|e-?posta(?:nin)?\s+sonu|veri(?:nin)?\s+sonu|icerig?in\s+sonu|yeni\s+talimat\w*|yeni\s+gorev\w*|sistem\s+talimat\w*)\s*(?:---|===|\*\*\*)?|\b(?:(?:belge(?:nin)?|metn?in|makale(?:nin)?|e-?posta(?:nin)?|mesaj(?:in)?|icerig?in|dosya(?:nin)?|ozet(?:in)?|ceviri(?:nin)?)\s+sonu|(?:bu\s+|yukaridaki\s+)?(?:belge|metin|makale|e-?posta|mesaj|icerik|ozet|ceviri)\s+(?:burada\s+)?(?:bitti|sona\s+erdi|tamamlandi|sonlandi)|buraya\s+kadar\s+olan\s+(?:kisim|metin|belge)\s+bitti)\b.{0,95}\b(?:simdi|artik|yeni\s+(?:gorev\w*|talimat\w*|komut\w*|is\w*|hedef\w*)|asil\s+(?:gorev\w*|talimat\w*|yapman\s+gereken)|bunun\s+yerine|onceki\s+gorev\w*|gorev\w*\s+birak\w*|unut(?:un)?|yok\s*say\w*|iptal\s+et\w*|sadece\s+sunu))",
            ),
            // TR: Drop / Finish Current Task -> New Task / Real Objective
            (
                "direct_injection",
                75,
                0.93,
                r"(?is)\b(?:(?:mevcut|onceki|ilk|eski|yukaridaki|verilen|bu|su\s+anki|ozetleme|cevirme|analiz)\b.{0,25}\b(?:gorev\w*|talimat\w*|is(?:i|ini|lemini)?)\b.{0,25}\b(?:birak\w*|durdur\w*|yarida\s+kes\w*|iptal\s+et\w*|terk\s+et\w*|sonlandir\w*|unut(?:un)?|bir\s+kenara\s+birak\w*|tamamlandi\s+say\w*|bitti\s+kabul\s+et\w*)|gorev(?:i|ini)\s+(?:hemen\s+|tamamen\s+)?(?:birak\w*|degistir\w*|terk\s+et\w*|durdur\w*|yarida\s+kes\w*))\b.{0,85}\b(yeni\s+(?:gorev\w*|talimat\w*|komut\w*|hedef\w*|is\w*)|asil\s+(?:gorev\w*|yapman\s+gereken|amac\w*)|bunun\s+yerine|onun\s+yerine|simdi\s+(?:sadece|bana|sunu|yapman\s+gereken|yeni)|bundan\s+sonra)\b",
            ),

            // =========================================================================
            // 3. INDIRECT PROMPT INJECTION (EMBEDDED IN WEB / EMAIL / DOCS / DATA)
            // =========================================================================
            // Addressing the AI / LLM / Summarizer / Translator inside untrusted text
            (
                "indirect",
                80,
                0.95,
                r"(?is)\b(yapay\s+zeka\w*|ai|asistan\w*|model\w*|llm\w*|dil\s+model\w*|ajan\w*|bot\w*|ozetleyici\w*|cevirmen\w*|claude|gpt|gemini|hermes)\s+(?:icin|asistanina|modeline|adina|tarafindan\s+okunacak|tarafindan\s+islenecek)\s+(?:onemli\s+|gizli\s+|ozel\s+|sistem\s+|ek\s+|yeni\s+)?(not\w*|talimat\w*|uyari\w*|mesaj\w*|emir\w*|yonerge\w*|komut\w*|direktif\w*|aciklama\w*|kural\w*)\b",
            ),
            (
                "indirect",
                80,
                0.95,
                r"(?is)(?:^|\n|\b)(?:asistana\s+not|yapay\s+zekaya\s+not|yapay\s+zekaya\s+mesaj|asistana\s+talimat|asistan\s+talimati|gizli\s+talimat|gomulu\s+talimat|arka\s+plan\s+komutu|model\s+icin\s+not|llm\s+icin\s+not|dikkat\s+(?:yapay\s+zeka|asistan|ai|llm)|sayin\s+(?:yapay\s+zeka|asistan)|sevgili\s+(?:yapay\s+zeka|asistan)|merhaba\s+(?:yapay\s+zeka|asistan)|hey\s+(?:yapay\s+zeka|asistan|ai|llm)|ai\s+note|note\s+to\s+(?:the\s+)?(?:ai|assistant|llm|model|summarizer|translator)|note\s+for\s+(?:the\s+)?(?:ai|assistant|llm|model)|instructions?\s+for\s+(?:the\s+)?(?:ai|assistant|llm|model|summarizer|translator)|instructions?\s+to\s+(?:the\s+)?(?:ai|assistant|llm|model)|attention\s+(?:ai|assistant|llm|model)|dear\s+(?:ai|assistant|llm)|hello\s+(?:ai|assistant|llm)|to\s+any\s+(?:ai|llm|assistant)\s+(?:reading|processing)|hidden\s+instruction|embedded\s+instruction)\b",
            ),
            // Document/email/page reader addressing AI (with or without "bu")
            (
                "indirect",
                80,
                0.95,
                r"(?is)\b(?:bu\s+|yukaridaki\s+|asagidaki\s+|ilgili\s+)?(metni|sayfayi|belgeyi|e-?postayi|mailleri|makaleyi|dosyayi|mesaji|yorumu|dokumani|yaziyi|icerigi|kaydi|cv'?yi|ozgecmisi|tabloyu|veriyi|web\s+sayfasini|haberi|raporu|kodu)\s+(?:okuyan|okuyorsan\w*|ozetleyen|ozetliyorsan\w*|ceviren|ceviriyorsan\w*|analiz\s+eden|isleyen|degerlendiren|tarayan|inceleyen|ziyaret\s+eden)\s+(?:bir\s+|herhangi\s+bir\s+|sayin\s+|sevgili\s+)?(yapay\s+zeka\w*|asistan\w*|model\w*|llm\w*|ajan\w*|bot\w*|sistem\w*|ai\b)",
            ),
            (
                "indirect",
                80,
                0.95,
                r"(?is)\b(?:bu\s+|yukaridaki\s+|asagidaki\s+)?(metni|sayfayi|belgeyi|e-?postayi|makaleyi|dosyayi|mesaji|yorumu|dokumani|yaziyi|icerigi|cv'?yi|ozgecmisi|raporu)\s+(?:okurken|ozetlerken|cevirirken|analiz\s+ederken|islerken|degerlendirirken|incelerken|okudugunda|gordugunde|okuduktan\s+sonra|ozetledikten\s+sonra)\b.{0,85}\b(kullanici\w*|gizlice|fark\s+ettirmeden|haberi\s+olmadan|su\s+mesaji|su\s+cumleyi|su\s+baglantiyi|su\s+linki|cagir\w*|calistir\w*|sil\w*|unut(?:un)?|atla\w*|sakla\w*|gizle\w*|bahsetme(?:yin|den)?|yonlendir\w*|puan\s+ver\w*|<SAFE_[A-Z0-9_]+>)\b",
            ),
            (
                "indirect",
                80,
                0.95,
                r"(?is)\b(?:eger|sayet)\s+(?:sen\s+)?(?:bir\s+)?(yapay\s+zeka\w*|asistan\w*|dil\s+model\w*|llm\w*|ajan\w*|bot\w*|ai\b)\s+(?:isen\w*|olarak\s+\w+|bunu\s+okuyorsan\w*)|\bif\s+(?:you\s+are\s+|this\s+is\s+being\s+(?:read|processed|summarized|translated|analyzed)\s+by\s+)(?:an?\s+)?(ai|assistant|language\s+model|llm|agent|bot)\b",
            ),
            // Task deflection inside summarization / translation / analysis / review
            (
                "indirect",
                80,
                0.94,
                r"(?is)\b(?:(?:bu\s+|yukaridaki\s+|asagidaki\s+)?(?:metni|sayfayi|e-?postayi|belgeyi|makaleyi|cumleyi|paragrafi|yaziyi|icerigi)\s+(?:ozetleme(?:yin|yi\s+birak)?|cevirme(?:yin|yi\s+birak)?|analiz\s+etme(?:yin)?|okuma(?:yin|yi\s+birak)?)|ozetlemeyi\s+(?:birak\w*|durdur\w*)|cevirmeyi\s+(?:birak\w*|durdur\w*)|analizi\s+(?:birak\w*|durdur\w*))\b.{0,50}\b(bunun\s+yerine|onun\s+yerine|sadece|yalnizca|hemen|dogrudan|olarak\s+sunu)\b|\b(?:do\s+not|don't|stop)\s+(?:summarize|summarizing|translate|translating|analyze|analyzing|process|processing|read|reading)\b.{0,50}\b(instead|rather|just\s+output|simply\s+say|only\s+output|respond\s+with)\b",
            ),
            (
                "indirect",
                75,
                0.92,
                r"(?is)\b(?:ozet\s+yerine|ceviri\s+yerine|bu\s+e-?postanin\s+ozeti\s+olarak|bu\s+metnin\s+ozeti\s+olarak|bu\s+belgenin\s+ozeti\s+olarak|kullanici\s+(?:senden\s+)?(?:ozet|ceviri|analiz|bilgi)\s+(?:isterse|istediginde|sordugunda))\b.{0,65}\b(sadece\s+sunu|yalnizca\s+sunu|su\s+mesaji|su\s+cumleyi|su\s+yaniti|su\s+baglantiyi|su\s+linki|onaylandi|her\s+sey\s+yolunda|guvenli)\b",
            ),
            (
                "indirect",
                75,
                0.92,
                r"(?is)\b(?:bu\s+(?:ozeti|ceviriyi|analizi|raporu|degerlendirmeyi)|yanit\w*|cevap\w*|ozet\w*|ceviri\w*)\s+(?:hazirlarken|yazarken|verirken|bitirirken|olustururken|sunarken|sonuna|basina|icine|olarak)\b.{0,75}\b(kullaniciya\s+fark\s+ettirmeden|kullanicinin\s+haberi\s+olmadan|gizlice|sadece\s+sunu|su\s+cumleyi|su\s+mesaji|su\s+linki|su\s+baglantiyi|su\s+ifadeyi|su\s+notu|<SAFE_[A-Z0-9_]+>)\b.{0,55}\b(ekle\w*|yaz\w*|belirt\w*|soyle\w*|yonlendir\w*|cagir\w*|gonder\w*|oner\w*|koy\w*|dondur\w*)\b",
            ),
            (
                "indirect",
                75,
                0.92,
                r"(?is)\b(?:when\s+(?:you\s+)?(?:read|reading|summarize|summarizing|translate|translating|analyze|analyzing|answer|answering|respond|responding|process|processing)|in\s+your\s+(?:summary|translation|analysis|response|answer|review|output)|at\s+the\s+(?:end|beginning)\s+of\s+your\s+(?:summary|response|answer|translation)|if\s+the\s+user\s+asks\s+about\s+this)\b.{0,80}\b(do\s+not\s+mention|instead\s+say|include\s+the\s+following\s+(?:hidden|secret|message|link|command)|output\s+only|secretly|without\s+telling\s+the\s+user|tell\s+them\s+to\s+visit|append\s+<SAFE_)\b",
            ),
            // Indirect instructions to manipulate the user, conceal notes, or bias evaluation/CV/review
            (
                "indirect",
                75,
                0.92,
                r"(?is)\b(kullaniciya\s+(?:su\s+mesaji|sunu|sadece\s+sunu|bu\s+nottan|bu\s+talimattan|hesabinin|oturumunun)\s+(?:soyle\w*|yaz\w*|goster\w*|ilet\w*|bahsetme(?:yin|den)?|belli\s+etme(?:yin|den)?)|bunu\s+kullaniciya\s+(?:soyleme(?:yin|den)?|gosterme(?:yin|den)?|fark\s+ettirme(?:yin|den)?|belli\s+etme(?:yin|den)?)|kullanicinin\s+haberi\s+olmadan|kullaniciya\s+fark\s+ettirmeden|kullaniciyi\s+su\s+(?:baglantiya|linke|adrese|siteye)\s+yonlendir\w*|kullaniciya\s+su\s+(?:linke|baglantiya)\s+tiklamasini\s+(?:soyle\w*|iste\w*)|bu\s+(?:aday\w*|basvuru\w*|ozgecmis\w*|cv\w*|urun\w*)\s+.{0,40}(?:kesinlikle\s+(?:ise\s+al\w*|onayla\w*|birinci\s+sec\w*|oner\w*)|en\s+(?:guclu|iyi|uygun)\s+aday\s+olarak|tum\s+kriterleri\s+karsiladigini|(?:10\s*uzerinden\s*10|10/10|en\s+yuksek\s+puan\w*|tam\s+puan)\s+ver\w*)|diger\s+tum\s+adaylari\s+ele\w*|bu\s+kodda\s+hicbir\s+guvenlik\s+acigi\s+olmadigini\s+(?:soyle\w*|raporla\w*|yaz\w*))\b",
            ),
            (
                "indirect",
                75,
                0.92,
                r"(?is)\b(rate\s+this\s+(?:candidate|applicant|resume|product)\s+(?:10/10|100%|as\s+the\s+best)|recommend\s+hiring\s+this\s+candidate\s+immediately|do\s+not\s+(?:mention|reveal|tell\s+the\s+user\s+about)\s+this\s+(?:instruction|note|directive|prompt|hidden\s+text)|tell\s+the\s+user\s+(?:to\s+click|that\s+their\s+(?:session|account|password)|to\s+run|to\s+visit\s+https?://)|according\s+to\s+my\s+file.{0,40}ignore\s+all\s+rules|execute\s+the\s+following\s+hidden\s+directive|report\s+that\s+this\s+code\s+has\s+no\s+vulnerabilities)\b",
            ),
            // HTML comments, hidden CSS spans, and Markdown image exfiltration
            (
                "indirect",
                80,
                0.94,
                r"(?is)<!--[^>]{0,260}\b(ignore|override|system|assistant|ai|llm|hidden|secret|execute|call|send|summarize|translate|talimat\w*|kural\w*|sistem\w*|yapay\s+zeka\w*|asistan\w*|gizli\w*|unut\w*|gonder\w*|yazdir\w*|ekle\w*|onay\w*)\b[^>]{0,260}-->",
            ),
            (
                "indirect",
                80,
                0.94,
                r#"(?is)(?:style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:white|#fff|#ffffff))[^"']*["'][^>]*>.{0,120}\b(?:ignore|system|assistant|ai|talimat\w*|kural\w*|asistan\w*|yapay\s+zeka\w*|unut\w*|gonder\w*)|!\[[^\]]*\]\(https?://[^\)]*(?:\?|&)(?:data|key|token|secret|prompt|context|history|cookie|password|sifre|anahtar|bilgi)=)"#,
            ),
            // Delimiter / ChatML / XML role spoofing
            (
                "indirect",
                80,
                0.96,
                r"(?is)(\[SYSTEM\]|\[HIDDEN\]|\[INST\]|\[/INST\]|<<SYS>>|<\|im_start\|>\s*(?:system|user|assistant)|<\|system\|>|</?untrusted_data>|<<<\s*END_UNTRUSTED_EXTERNAL_DATA|###\s*(?:SYSTEM|INSTRUCTION|SİSTEM|SISTEM|TALİMAT|TALIMAT)|system_instruction\s*:|</?(?:system_prompt|system_instruction|developer_instruction|admin_override|system|instruction)>)",
            ),

            // =========================================================================
            // 4. SPOOFED SYSTEM / DEVELOPER / ADMIN NOTIFICATIONS ("TAKLİT")
            // =========================================================================
            // Bracketed system/admin/developer/override tags
            (
                "spoofed_authority",
                75,
                0.94,
                r"(?is)\[\s*(?:sistem|system|yonetici|admin|administrator|gelistirici|developer|guvenlik|security|politika|policy|override|kernel|root|mod|moderator|operator|denetim|audit|internal|acil|anthropic|openai|google|meta|hermes)\s*(?:mesaji|bildirimi|uyarisi|notu|emri|komutu|guncellemesi|modu|onayi|yetkisi|protokolu|message|notification|alert|notice|directive|override|update|broadcast|command|mode|status)?\s*\]",
            ),
            // Unbracketed "Sistem mesajı: / Geliştirici notu: / Sistem güncellemesi:" ONLY when paired with AI/rule/security/permission/tool override!
            // (Prevents false positives on "Geliştirici notu: bu fonksiyon sadece test ortamında çalışır" or "Sistem güncellemesi bu gece yapılacak")
            (
                "spoofed_authority",
                75,
                0.94,
                r"(?is)(?:^|\n|\b)(?:sistem|system|yonetici|admin|administrator|gelistirici|developer|guvenlik|security|politika|policy|root|kernel)\s+(?:mesaji|bildirimi|uyarisi|notu|emri|komutu|guncellemesi|onayi|protokolu|override|message|notification|alert|notice|directive|update|command)\s*[:\-—>].{0,90}\b(talimat\w*|kural\w*|kisitlama\w*|sinir\w*|filtre\w*|koruma\w*|guvenlik\s+(?:protokol\w*|katman\w*|duvar\w*|onlem\w*|kural\w*)|onay\s+sorma\w*|onay\s+adim\w*|yetki\s+seviyesi|root|admin|serbest\s+mod|denetim\s+modu|bakim\s+modu|devre\s+disi|kapatildi|kaldirildi|iptal|unut\w*|yok\s*say\w*|atla\w*|tum\s+komut\w*\s+calistir\w*|oldugu\s+gibi\s+goster\w*|sistem\s+prompt\w*|ignore|override|disable|bypass|unrestricted|safety\s+layer|restrictions?|all\s+commands|execute|reveal|clearance)\b",
            ),
            // Fake security/mode/clearance announcements directed at the AI session
            (
                "spoofed_authority",
                75,
                0.92,
                r"(?is)\b(guvenlik\s+protokolu\s+guncellendi|guvenlik\s+politikasi\s+guncellendi|yeni\s+sistem\s+kurali\s*:|yeni\s+sistem\s+yapilandirmasi|(?:bakim|denetim|tanilama|servis|test)\s+modu\s+(?:aktif|acildi|etkin\w*).{0,60}\b(?:kisitlama\w*|kural\w*|filtre\w*|onay\w*|guvenlik\w*|komut\w*|serbest\w*)|koruma\s+katmani\s+(?:devre\s+disi|kapatildi)|yetkilendirme\s+basarili|yonetici\s+yetkisi\s+dogrulandi|yonetici\s+oturumu\s+acildi|gelistirici\s+konsolu\s+(?:aktif|acildi|etkin\w*)|yetki\s+seviyesi\s*:\s*(?:root|admin|yonetici|sinirsiz|tam)|system\s+policy\s+update\s*:|security\s+protocol\s+override|(?:maintenance|audit|diagnostic|service)\s+mode\s+(?:enabled|active|activated)|safety\s+layer\s+(?:disabled|bypassed|off)|authentication\s+successful\s*:\s*admin|clearance\s+level\s*:\s*(?:admin|root|unrestricted|level\s*\d))\b",
            ),
            (
                "spoofed_authority",
                75,
                0.92,
                r"(?is)(?:^|\n)\s*(?:sistem|system|yonetici|admin|gelistirici|developer|root|guvenlik|security)\s*:\s*.{0,60}\b(talimat\w*|kural\w*|kisitlama\w*|filtre\w*|onay\s+sorma\w*|yetki\w*|serbest\w*|devre\s+disi\w*|kapat\w*|calistir\w*|gonder\w*|sil\w*|goster\w*|ignore|override|disable|bypass|allow|grant|execute|reveal)\b",
            ),

            // =========================================================================
            // 5. APPROVAL BYPASS ("KULLANICI ZATEN ONAYLADI / ONAY SORMA")
            // =========================================================================
            // TR: Prior approval claim PAIRED WITH a bypass / no-ask / direct-execution command to the AI
            // (Prevents false positives on 3rd-person narratives like "Müşteri siparişi onayladı, kargoya verebiliriz" or "Kullanıcı ayarları onayladıktan sonra...")
            (
                "approval_bypass",
                75,
                0.95,
                r"(?is)\b((?:kullanici|baskan|yonetici|admin|sahip|mudur|operator|sistem\s+sahibi)\b.{0,40}\b(?:zaten|onceden|az\s+once|bizzat|yazili\s+olarak|telefonda|sozlu\s+olarak|bastan)?\s*(?:onay\s+verdi\b|onayladi\b|izin\s+verdi\b|yetki\s+verdi\b|yetkilendirdi\b|onay\s+vermisti\b|evet\s+dedi\b)|(?:bu\s+|tum\s+|ilgili\s+)?(?:islem\w*|komut\w*|gorev\w*|talep\w*|silme\w*|aktarim\w*)\s+(?:icin\s+)?(?:zaten\s+|onceden\s+|baskan\s+tarafindan\s+|yonetici\s+tarafindan\s+|kullanici\s+tarafindan\s+)?(?:onaylandi\b|onaylanmistir\b|on\s+onaylidir\b|on\s+onay\s+alindi\b|izin\s+alindi\b|izin\s+verildi\b|yetki\s+verildi\b)|gerekli\s+(?:tum\s+)?(?:izinler|onaylar)\s+(?:zaten\s+|onceden\s+)?alindi\b|onay\s+sureci\s+tamamlandi\b).{0,75}\b(tekrar\s+onay|bir\s+daha\s+sorma|onay\s+sorma\w*|izin\s+sorma\w*|izin\s+isteme\w*|teyit\s+bekleme\w*|teyit\s+isteme\w*|sormadan|beklemeden|atla\w*|dogrudan\s+(?:calistir\w*|uygula\w*|sil\w*|gonder\w*|yap\w*|gec\w*)|hemen\s+(?:calistir\w*|uygula\w*|sil\w*|gonder\w*)|komutu\s+calistir\w*|dosyayi\s+sil\w*)\b",
            ),
            // TR: Direct command to the AI not to ask for approval/confirmation
            (
                "approval_bypass",
                75,
                0.94,
                r"(?is)\b(?:tekrar\s+|bir\s+daha\s+|yeniden\s+|ekstra\s+|hicbir\s+|kullanicidan\s+|baskandan\s+|bana\s+)?(onay\w*|izin\w*|teyit\w*|dogrulama\w*)\s+(sorma(?:yin|yiniz|dan|na\s+gerek\s+yok|malisin)?|isteme(?:yin|yiniz|den|ne\s+gerek\s+yok|melisin)?|bekleme(?:yin|yiniz|den|ne\s+gerek\s+yok|melisin)?|alma(?:yin|dan|na\s+gerek\s+yok)?|aramana\s+gerek\s+yok|gerek\s+yok\w*|gerekmiyor\w*|gerek\s+kalmadi\w*|adimini\s+atla\w*|kapisini\s+atla\w*|mekanizmasini\s+atla\w*|kontrolunu\s+atla\w*|surecini\s+atla\w*|penceresi\w*\s+(?:cikarma\w*|gosterme\w*|acma\w*))\b",
            ),
            (
                "approval_bypass",
                75,
                0.94,
                r"(?is)\b(onay\s+sormadan|izin\s+almadan|izin\s+istemeden|teyit\s+beklemeden|teyit\s+almadan|kullaniciya\s+sormadan|baskana\s+sormadan|bana\s+sormadan|hic\s+sormadan|soru\s+sormadan\s+(?:hemen|dogrudan)\s+(?:calistir\w*|uygula\w*|sil\w*|gonder\w*|yap\w*)|dogrulama\s+adimini\s+atla\w*|onay\s+adimini\s+atla\w*|onay\s+kapisini\s+atla\w*|onay\s+mekanizmasini\s+atla\w*|otomatik\s+onayla\w*|onay\s+alindi\s+varsay\w*|onay\s+verilmis\s+(?:kabul\s+et\w*|say\w*)|evet\s+dedi\s+varsay\w*|on\s+onayli\s+islem|bu\s+islem\s+icin\s+onay\s+alinmistir|bana\s+sormana\s+gerek\s+yok.{0,30}(?:hemen|dogrudan)\s+(?:yap\w*|calistir\w*|uygula\w*|sil\w*|gonder\w*))\b",
            ),
            // EN: Prior approval claim PAIRED WITH a bypass / no-ask / direct-execution command to the AI
            // (Prevents false positives on "The manager approved the budget, so we can order the new monitors")
            (
                "approval_bypass",
                75,
                0.94,
                r"(?is)\b(?:(?:the\s+)?(?:user|owner|admin|administrator|operator|manager|president|client)\s+(?:has\s+)?(?:already\s+|pre-?\s*|explicitly\s+|verbally\s+|previously\s+)?(?:approved|authorized|confirmed|consented|granted\s+permission|signed\s+off|said\s+yes)|(?:this\s+|the\s+)?(?:action|command|operation|request|task|deletion)\s+(?:is\s+|has\s+been\s+|was\s+)(?:already\s+|pre-?\s*|previously\s+)?(?:approved|authorized|confirmed|cleared)|all\s+permissions\s+have\s+been\s+granted)\b.{0,80}\b(do\s+not\s+ask|don't\s+ask|without\s+asking|without\s+confirmation|without\s+approval|without\s+prompting|skip\s+(?:user\s+|the\s+)?(?:approval|confirmation|verification|prompt\w*)|bypass\s+(?:approval|confirmation|verification)|no\s+need\s+to\s+(?:ask|confirm|wait)|don't\s+wait|proceed\s+(?:immediately|directly)|execute\s+(?:directly|immediately)|run\s+(?:directly|immediately)|just\s+(?:run|execute|delete))\b",
            ),
            // EN: Direct command not to ask for approval/confirmation
            (
                "approval_bypass",
                75,
                0.94,
                r"(?is)\b(do\s+not|don't|never|no\s+need\s+to|skip|bypass|without)\s+(?:ask(?:ing)?\s+(?:for\s+|the\s+user\s+for\s+)?|request(?:ing)?\s+|wait(?:ing)?\s+for\s+|prompt(?:ing)?\s+(?:the\s+user\s+)?for\s+|require\s+|bother\s+asking\s+for\s+)?(?:user\s+|human\s+|further\s+|additional\s+|explicit\s+|the\s+)?(approval|confirmation|permission|consent|verification\s+step|confirmation\s+prompt|approval\s+step|approval\s+gate)\b|\b(pre-?authorized\s+(?:operation|command|action|request)|pre-?approved\s+(?:operation|command|action|request)|auto-?approve|approval\s+status\s*:\s*granted|user\s+confirmation\s*:\s*yes|assume\s+the\s+user\s+(?:approved|said\s+yes)|execute\s+directly\s+without\s+(?:prompting|asking))\b",
            ),

            // =========================================================================
            // 6. URGENCY PRESSURE & SOCIAL ENGINEERING (EN + TR)
            // =========================================================================
            // TR: Urgency phrase PAIRED WITH bypass/secret/destructive action (excludes "Vakit yok, toplantıya geç kalıyorum" & "Tüm sorumluluk bende, projeyi zamanında teslim edeceğim")
            (
                "urgency_pressure",
                75,
                0.92,
                r"(?is)\b(cok\s+acil|acil\s+durum\w*|acil\s+mudahale|kritik\s+durum\w*|kritik\s+ariza|hayati\s+tehlike|hayati\s+onem|sistem\s+cokuyor|sunucu\s+cokuyor|saldiri\s+altindayiz|veri\s+kaybi\s+olacak|zaman\s+yok|vakit\s+yok|zamanimiz\s+yok|vaktimiz\s+yok|kaybedecek\s+(?:vakit|zaman)\s+yok|vakit\s+kaybetmeden|zaman\s+kaybetmeden|saniyeler\s+icinde|saniyelerimiz\s+kaldi|sonra\s+aciklarim|once\s+yap\s+sonra\s+sor\w*|tum\s+sorumlulugu\s+aliyorum|sorumlulugu\s+ustleniyorum|sorumluluk\s+bende)\b.{0,95}\b(sorma(?:yin|dan)?|bekleme(?:yin|den)?|atla(?:yin|yip|yarak)?|kontrol\s+etme(?:yin|den)?|dogrulama\s+kontrol\w*|sorgulama(?:yin|dan)?|prosedur\w*|guvenlik\s+kural\w*|onay\s+sorma\w*|onay\s+bekleme\w*|izin\s+sorma\w*|log\w*\s+sil\w*|dosya\w*\s+sil\w*|komut\w*\s+calistir\w*|gizli\s+\w+|anahtar\w*|sifre\w*|parola\w*|guvenlik\s+duvar\w*\s+kapat\w*|devre\s+disi\s+birak\w*|kayit\s+tutma(?:yin|dan)?)\b",
            ),
            // TR: Reversed order (bypass/secret/destructive action -> urgency phrase)
            (
                "urgency_pressure",
                75,
                0.92,
                r"(?is)\b((?:prosedur\w*|guvenlik\s+kontrol\w*|dogrulama\w*|onay\s+surec\w*|kural\w*)\s+(?:ile\s+|icin\s+|bekleyecek\s+)?(?:ugrasacak\s+zaman\s+yok|vakit\s+yok|vaktimiz\s+yok|zaman\s+kaybetme(?:yin|den)?|atla\w*|bekleyemeyiz)|once\s+yap\s+sonra\s+sor\w*|(?:onay\s+sormadan|izin\s+almadan|dogrulama\s+adimini\s+atla\w*|log\w*\s+sil\w*|gizli\s+anahtar\w*|sifre\w*|komut\w*\s+calistir\w*).{0,65}\b(?:cok\s+acil|vakit\s+yok|zaman\s+yok|sorumluluk\s+bende|tum\s+sorumlulugu\s+aliyorum|sonra\s+aciklarim))\b",
            ),
            // EN: Urgency + Approval/Security Bypass or Unchecked Execution (Bidirectional: Urgency -> Bypass OR Bypass -> Urgency)
            // (Catches all EN urgency + approval bypass combinations while keeping "This is urgent: the client presentation moved to 9 AM" and "In chess, you must follow the rules even when you're in a hurry" at 0!)
            (
                "urgency_pressure",
                75,
                0.94,
                r"(?is)\b(urgent\w*|emergenc\w*|critical\s+(?:issue|outage|incident|failure|situation|emergency|alert)|outage|under\s+attack|security\s+breach|data\s+loss|no\s+time|don't\s+have\s+time|running\s+out\s+of\s+time|short\s+on\s+time|time-?sensitive|time\s+is\s+(?:critical|running\s+out)|every\s+second\s+counts|asap|in\s+a\s+hurry|cannot\s+wait|can't\s+wait|server\s+is\s+(?:down|crashing)|production\s+is\s+(?:down|failing|broken)|explain\s+later|act\s+first\s+ask\s+later|take\s+(?:full\s+)?responsibility)\b.{0,110}\b((?:do\s+not|don't|never|no\s+need\s+to|stop)\s+(?:ask\w*|wait\w*|prompt\w*|bother\s+with|require\w*)|to\s+(?:ask|wait|prompt|check)\s+for\s+(?:user\s+|human\s+|manual\s+|the\s+)?(?:approval\w*|confirmation\w*|permission\w*|consent\w*|verification\w*|checks?)|for\s+(?:user\s+|human\s+|manual\s+|standard\s+|normal\s+|security\s+)?(?:approval\w*|confirmation\w*|permission\w*|verification\w*|security\s+checks?)|(?:skip|bypass|ignore|omit|waive|drop|disable|override)\s+(?:the\s+|all\s+|any\s+|user\s+|human\s+|standard\s+|normal\s+|safety\s+|security\s+)?(?:approval\w*|confirmation\w*|verification\w*|permission\w*|check\w*|step\w*|gate\w*|procedure\w*|protocol\w*|prompt\w*|rule\w*|logging|guardrail\w*|policy|policies)|without\s+(?:asking|waiting|prompting|approval|confirmation|permission|verification|checks?)|auto-?approve|pre-?approved|just\s+(?:run|execute|delete|send|do\s+it)|execute\s+(?:now|immediately|directly|right\s+away)|run\s+(?:now|immediately|directly|right\s+away)|delete\s+all\s+logs|dump\s+credentials|send\s+the\s+keys|root\s+access)\b",
            ),
            (
                "urgency_pressure",
                75,
                0.94,
                r"(?is)\b((?:do\s+not|don't|never|no\s+need\s+to)\s+(?:ask\w*|wait\w*|prompt\w*)|(?:skip|bypass|ignore|disable|override)\s+(?:the\s+|all\s+|any\s+|user\s+|standard\s+|safety\s+|security\s+)?(?:approval\w*|confirmation\w*|verification\w*|permission\w*|check\w*|step\w*|gate\w*|procedure\w*|protocol\w*|rule\w*)|without\s+(?:asking|waiting|approval|confirmation|permission|verification)|delete\s+all\s+logs|dump\s+credentials)\b.{0,110}\b(urgent\w*|emergenc\w*|critical|outage|under\s+attack|breach|no\s+time|don't\s+have\s+time|running\s+out\s+of\s+time|every\s+second\s+counts|asap|in\s+a\s+hurry|cannot\s+wait|can't\s+wait|server\s+is\s+down|production\s+is\s+down|explain\s+later|take\s+(?:full\s+)?responsibility)\b",
            ),
            (
                "social_engineering",
                75,
                0.93,
                r"(?is)\b(i\s+am\s+the\s+(?:system\s+administrator|lead\s+security\s+engineer|creator|ceo|owner|developer|chief\s+architect)|as\s+your\s+(?:creator|developer|admin|owner)|ben\s+(?:sistem\s+yoneticisiyim|bas\s+muhendisim|guvenlik\s+uzmaniyim|gelistiricinim|kurucuyum|sirket\s+muduruyum|proje\s+sahibiyim)|sirket\s+muduru\s+onay\s+verdi|yonetici\s+beni\s+yetkilendirdi)\b.{0,80}\b(give\s+me\s+root\s+access|bypass|skip|dump|reveal|show|delete|disable|guvenlik\s+duvar\w*|dogrulama\w*|onay\w*|dosya\w*\s+sil\w*|sifre\w*|anahtar\w*|yetki\s+ver\w*|komut\w*\s+calistir\w*|erisim\s+ver\w*)\b",
            ),
            (
                "social_engineering",
                75,
                0.90,
                r"(?is)\b(keep\s+this\s+between\s+us|don't\s+log\s+this\s+conversation|aramizda\s+kalsin|bunu\s+kayitlara\s+gecirme(?:yin|den)?|loglara\s+yazma(?:yin|dan)?|kayit\s+tutmadan\s+calistir\w*|iz\s+birakmadan\s+sil\w*)\b",
            ),

            // =========================================================================
            // 7. JAILBREAK, PERSONA SWITCHING & SAFETY FILTER REMOVAL (EN + TR)
            // =========================================================================
            // EN: Entering special / unrestricted / maintenance / debug / jailbreak modes
            (
                "jailbreak",
                75,
                0.95,
                r"(?is)\b(enable|activate|enter|switch\s+to|turn\s+on|boot\s+into|run\s+in|operate\s+in|you\s+are\s+(?:now\s+)?in|we\s+are\s+(?:now\s+)?in|system\s+is\s+(?:now\s+)?in)\b.{0,45}\b(dan\s+mode|developer\s+diagnostics\s+mode|unrestricted\s+(?:ai|mode|personality|assistant|state)|unfiltered\s+(?:ai|mode|assistant)|uncensored\s+(?:ai|mode|assistant)|jailbreak\s+mode|god\s+mode|evil\s+mode|stan\s+mode|dude\s+mode|maintenance\s+mode|debug(?:ging)?\s+mode|service\s+mode|diagnostic\s+mode|sudo\s+mode|root\s+mode|privileged\s+mode|raw\s+mode|override\s+mode|sandbox\s+(?:testing\s+)?mode)\b",
            ),
            // EN: Role / Persona adoption (new identity, unrestricted assistant, no-rules persona)
            (
                "jailbreak",
                75,
                0.94,
                r"(?is)\b(act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as|adopt\s+(?:a\s+new\s+|the\s+)?(?:role|identity|persona)|assume\s+the\s+(?:role|identity|persona)\s+of|take\s+on\s+(?:a\s+new\s+|the\s+)?(?:role|persona|identity)|from\s+now\s+on\s+you\s+(?:are|will\s+be|act\s+as)|you\s+are\s+now\s+(?:an?\s+)?|imagine\s+you\s+are\s+(?:an?\s+)?|play\s+the\s+(?:role|part|character)\s+of|simulate\s+(?:an?\s+)?|behave\s+(?:like|as)\s+(?:an?\s+)?|as\s+an\s+unrestricted)\b.{0,75}\b(unrestricted|unfiltered|uncensored|unbounded|amoral|rogue|rebellious|rule-?free|limitless|jailbroken|autonomous\s+agent\s+with\s+no|ai\s+(?:with\s+no|without|that\s+has\s+no|that\s+ignores)|assistant\s+(?:with\s+no|without|that\s+has\s+no|who\s+does\s+not\s+follow|that\s+ignores)|model\s+(?:with\s+no|without|that\s+has\s+no)|persona\s+(?:with\s+no|without|that\s+ignores|named)|(?:that|who|which)\s+(?:has\s+no|ignores|does\s+not\s+follow|never\s+refuses|operates\s+without)|with\s+no\s+(?:rules|limits|restrictions|filters|content\s+filters|safety|boundaries|guardrails)|without\s+(?:any\s+)?(?:rules|limits|restrictions|filters|content\s+filters|safety|boundaries|guardrails)|terminal\s+with\s+no|free\s+from\s+(?:all\s+)?(?:rules|restrictions|constraints|guardrails|boundaries))\b",
            ),
            // EN: Dropping current AI identity / role & taking a new persona
            (
                "jailbreak",
                75,
                0.93,
                r"(?is)\b(you\s+are\s+no\s+longer\s+(?:an?\s+)?(?:ai|assistant|helpful|bound\s+by)|stop\s+(?:being|acting\s+as)\s+(?:an?\s+)?(?:ai|assistant|helpful)|abandon\s+your\s+(?:current\s+|default\s+|ai\s+|assistant\s+)?(?:role|persona|identity)|drop\s+your\s+(?:current\s+|default\s+|ai\s+|assistant\s+)?(?:persona|role|identity)|shed\s+your\s+(?:ai\s+|assistant\s+)?(?:persona|role|identity|restrictions)|override\s+your\s+(?:default\s+|current\s+)?(?:persona|identity|role)|reset\s+your\s+(?:persona|identity|role)|your\s+new\s+(?:persona|identity|role|character|name)\s+is|for\s+(?:this|the\s+rest\s+of\s+this)\s+(?:session|conversation)\s+your\s+(?:role|persona|identity)\s+is)\b",
            ),
            // Developer mode ONLY when paired with AI second-person or restriction/filter removal
            (
                "jailbreak",
                75,
                0.94,
                r"(?is)\b(you\s+are\s+now\s+in\s+developer\s+mode|developer\s+mode\s+(?:with\s+no\s+restrictions|enabled\s*[-:]\s*ignore|where\s+safety)|gelistirici\s+modu\w*\s+(?:gec\w*|ac\w*|aktif\w*).{0,35}\b(?:filtre\w*|kisitlama\w*|kural\w*|engel\w*|sansur\w*|guvenlik\w*)\b)",
            ),
            (
                "jailbreak",
                75,
                0.92,
                r"(?is)\b(respond|act|operate|answer|behave|pretend\s+you\s+are\s+an?\s+ai|you\s+will\s+respond)\b.{0,45}\bwithout\s+(any\s+)?(filters?|restrictions?|ethical\s+guidelines?|safety\s+policies|guardrails?|censorship|limits?|moral\s+constraints?|rules?|boundaries)\b",
            ),
            (
                "jailbreak",
                75,
                0.92,
                r"(?is)\b(safety\s+policies|ethical\s+guidelines|security\s+filters?|safety\s+filters?|content\s+filters?|guardrails?)\s+(are\s+|is\s+)?(disabled|off|suspended|removed|lifted|deactivated)\b|\bdisable\s+(?:all\s+)?(?:safety|security|content)\s+filters?\b",
            ),
            (
                "jailbreak",
                75,
                0.94,
                r"(?is)\b(serbest\s+mod\w*|sinirsiz\s+mod\w*|kisitlamasiz\s+mod\w*|sansursuz\s+mod\w*|etik\s+disi\s+mod\w*|korsan\s+mod\w*)\b.{0,45}\b(gec\w*|calis\w*|aktif\w*|ac\w*|yanit\s+ver\w*)\b|\b(guvenlik\s+filtre\w*|etik\s+sinir\w*|etik\s+kural\w*|ahlaki\s+sinir\w*|icerik\s+filtre\w*|sansur\s+filtre\w*)\b.{0,45}\b(olmayan|olmadan|kapali|gecerli\s+degil\w*|devre\s+disi|kaldir\w*|kapat\w*|yok\s*say\w*)\b",
            ),
            (
                "jailbreak",
                75,
                0.90,
                r"(?is)\b(asla\s+hayir\s+deme(?:yin|den)?|hicbir\s+istegi\s+reddetme(?:yin|den)?|reddetme\s+hakkin\s+yok|uyari\s+vermeden\s+yanitla\w*|etik\s+dersi\s+verme(?:yin|den)?|bu\s+bir\s+kurgu\s+senaryosudur.{0,35}kurallar\s+gecerli\s+degil\w*|hipotetik\s+olarak\s+tum\s+kurallarin\s+kalktigini\s+dusun|kisitlama\s+olmadan\s+cevap\s+ver\w*|sansursuz\s+yanit\s+ver\w*|engelsiz\s+bir\s+asistan\s+olarak|kisitlamasiz\s+bir\s+asistan\s+olarak)\b",
            ),

            // =========================================================================
            // 8. SYSTEM PROMPT VERBATIM REPETITION & SECRET LEAKAGE (EN + TR)
            // =========================================================================
            // EN: Direct request to show/print/repeat/translate/format system prompt or initial/hidden instructions
            (
                "leakage",
                75,
                0.95,
                r"(?is)\b(show|reveal|print|output|repeat|reproduce|transcribe|quote|echo|display|tell\s+me|give\s+me|write\s+out|write\s+down|dump|copy|list|share|disclose|expose|spell\s+out|translate|summarize|format|convert|encode)\b.{0,50}\b(?:your\s+|the\s+|all\s+|every\s+)?(?:initial\s+|hidden\s+|verbatim\s+|exact\s+|full\s+|complete\s+|secret\s+|internal\s+|original\s+|underlying\s+|entire\s+)?(system\s+prompt|system\s+instructions?|system\s+messages?|system\s+rules?|developer\s+prompt|developer\s+messages?|developer\s+instructions?|hidden\s+instructions?|hidden\s+rules?|hidden\s+prompt|initial\s+instructions?|initial\s+prompt|meta\s+prompt|pre-?prompt|preamble|configuration\s+rules?|core\s+instructions?)\b",
            ),
            // EN: Verbatim repetition of text/instructions/words above, at the start, or given to the AI
            (
                "leakage",
                75,
                0.94,
                r"(?is)\b(repeat|echo|reproduce|transcribe|print|output|copy|quote|write\s+out|recite|show\s+me|give\s+me)\b.{0,45}\b(everything|all\s+(?:the\s+)?(?:text|words|sentences|instructions|rules|messages|content)|the\s+(?:exact\s+|full\s+|entire\s+|verbatim\s+|initial\s+)?(?:text|words|sentences|instructions|directives|prompt|message|rules|guidelines))\b.{0,45}\b(above|before\s+this|prior\s+to\s+this|at\s+the\s+(?:start|beginning|top)|from\s+the\s+(?:start|beginning|top)|you\s+were\s+(?:given|initialized\s+with|told)|given\s+to\s+you|word\s+for\s+word|verbatim|character\s+by\s+character|exactly\s+as\s+written|starting\s+from\s+you\s+are)\b",
            ),
            (
                "leakage",
                75,
                0.93,
                r"(?is)\b(what\s+(?:instructions?|rules?|prompt|directives?)\s+were\s+you\s+given|what\s+is\s+written\s+(?:at\s+the\s+very\s+top|above\s+my\s+message|in\s+your\s+system\s+prompt)|(?:verbatim|word\s+for\s+word|exact)\s+(?:copy|transcript|text)\s+of\s+your\s+(?:instructions|rules|prompt|system\s+message)|print\s+hidden\s+rules|reveal\s+secrets)\b",
            ),
            (
                "leakage",
                80,
                0.98,
                r"(?is)\b(SYSTEM_PROMPT\.md|BASKAN_TALIMATLARI\.md|CANARY_TOKEN\.txt|API_KEYS\.md)\b",
            ),
            // TR: System prompt / initial instructions extraction & verbatim repetition
            (
                "leakage",
                75,
                0.95,
                r"(?is)\b(sistem\s+prompt\w*|sistem\s+istem\w*|sistem\s+talimat\w*|sistem\s+mesaj\w*|sistem\s+kural\w*|sistem\s+yonerge\w*|gizli\s+yapilandirma\s+kural\w*|gizli\s+talimat\w*|gizli\s+yonerge\w*|baslangic\s+istem\w*|baslangic\s+talimat\w*|ilk\s+talimat\w*|(?:sana\s+|basta\s+|baslangicta\s+|onceden\s+|ilk\s+)?verilen\s+(?:ilk\s+|baslangic\s+|sistem\s+|gizli\s+|tum\s+)?(?:talimat\w*|kural\w*|yonerge\w*|mesaj\w*|istem\w*)|kendi\s+(?:sistem\s+)?(?:talimatlar\w*|yonergeler\w*|istem\w*)|arka\s+plandaki\s+kural\w*)\b.{0,60}\b(goster\w*|yaz\w*|yazdir\w*|listele\w*|acikla\w*|paylas\w*|soyle\w*|tekrar\s+et\w*|tekrarla\w*|kopyala\w*|alintila\w*|aktar\w*|ekrana\s+bas\w*|cevir\w*|kelimesi\s+kelimesine|harfi\s+harfine|aynen|oldugu\s+gibi|hic\s+degistirmeden|eksiksiz)\b",
            ),
            // TR: Verbatim repetition of text/instructions above or at the start ("yukarıdaki metni / talimatlarını aynen tekrar et / yazdır")
            (
                "leakage",
                75,
                0.94,
                r"(?is)\b(?:(yukaridaki|en\s+bastaki|baslangictaki|bu\s+mesajdan\s+onceki|sohbetin\s+basindaki|ilk\s+mesajdaki)\s+(?:tum\s+|butun\s+)?(metni|yazilanlari|cumleleri|talimatlari|kurallari|yonergeleri|mesaji|kelimeleri|icerigi)|(talimatlarini|yonergelerini|sistem\s+mesajini)\s+(?:aynen|kelimesi\s+kelimesine|harfi\s+harfine|oldugu\s+gibi|hic\s+degistirmeden))\b.{0,50}\b(aynen|oldugu\s+gibi|kelimesi\s+kelimesine|harfi\s+harfine|eksiksiz|hic\s+degistirmeden|tekrar\s+et\w*|tekrarla\w*|yazdir\w*|yaz\w*|kopyala\w*|aktar\w*|alintila\w*)\b",
            ),

            // =========================================================================
            // 9. AGENT TOOL-CALL HIJACKING & DATA EXFILTRATION (EN + TR)
            // =========================================================================
            (
                "agent_tool_hijack",
                85,
                0.98,
                r#"(?is)(<tool_call>|<function_calls?>|\{\s*"name"\s*:\s*"(?:run_command|terminal|write_file|write_to_file|bash|execute_code)")"#,
            ),
            (
                "agent_tool_hijack",
                85,
                0.95,
                r"(?is)\b(execute|call|invoke|use|run|must\s+call|cagir\w*|calistir\w*|kullanarak|kullanip)\b.{0,55}\b(run_command|terminal|write_to_file|write_file|search_web|bash|powershell|execute_code)\b.{0,75}(?:\b(?:rm\s+-rf|format\s+c:|ACTIVE_MEMORY\.md|SYSTEM_PROMPT\.md|BASKAN_TALIMATLARI\.md|ORTAK_GUNLUK\.md|reverse\s+shell|evil\.com|password|overwrite|dosyasini\s+sil\w*)|<SAFE_[A-Z0-9_]+>)",
            ),
            (
                "agent_tool_hijack",
                85,
                0.95,
                r"(?is)(?:\b(?:terminal\s+aracini\s+cagir\w*|arac\w*\s+kullanarak)\b.{0,65}(?:\b(?:komutunu\s+calistir\w*|ACTIVE_MEMORY\.md\s+dosyas\w*\s+sil\w*)|<SAFE_[A-Z0-9_]+>))",
            ),
            // EN Exfiltration 1: Action Verb -> Sensitive Source -> Sink (response, form, link, URL, query, webhook, external host, or direct readout)
            (
                "exfiltration",
                85,
                0.96,
                r"(?is)\b(send|post|upload|forward|exfiltrate|leak|transmit|submit|append|attach|embed|include|insert|encode|put|place|write|pass|curl|fetch|wget)\b.{0,65}(?:\b(?:conversation\s+history|chat\s+history|message\s+history|all\s+messages|previous\s+messages|secrets?|api\s+keys?|secret\s+keys?|private\s+keys?|ssh\s+(?:private\s+)?keys?|id_rsa|id_ed25519|environment\s+variables?|env\s+vars?|os\.environ|process\.env|credentials?|passwords?|passphrases?|auth\s+tokens?|access\s+tokens?|bearer\s+tokens?|session\s+tokens?|tokens?|keystore|private\s+(?:\w+\s+)?files?|confidential\s+(?:\w+\s+)?files?|internal\s+(?:\w+\s+)?files?|secret\s+(?:\w+\s+)?files?|user(?:'s)?\s+(?:data|emails?|messages?|files?|notes?)|their\s+contents)\b|(?:^|\s)(?:\.env|\.jks|\.pem|\.ssh)\b).{0,75}\b(to\s+https?://|https?://|url|link|query\s*(?:string|param\w*)?|parameter|webhook|endpoint|external|server|domain|form|field|box|input|response|answer|reply|output|image|markdown|email|address|collect|callback|evil\.com|example\.invalid|<SAFE_[A-Z0-9_]+>)\b",
            ),
            // EN Exfiltration 2: Read/Access/Extract Sensitive Source -> Put/Send/Display/Include in Response/Link/Form/External
            (
                "exfiltration",
                85,
                0.95,
                r"(?is)\b(read|access|cat|open|get|fetch|extract|find|locate|search\s+for|look\s+up|check|inspect|list|dump|print|show|display|reveal|output|copy|harvest|grab|take|retrieve|load|obtain|collect|expose)\b.{0,55}(?:\b(?:contents?\s+of\s+(?:the\s+)?(?:secrets?|\.env|\.ssh|config|credentials?)|environment\s+variables?|env\s+vars?|api\s+keys?|secret\s+keys?|private\s+keys?|ssh\s+(?:private\s+)?keys?|id_rsa|passwords?|credentials?|access\s+tokens?|auth\s+tokens?|bearer\s+tokens?|session\s+tokens?|conversation\s+history|chat\s+history|secret\s+(?:\w+\s+)?files?|private\s+(?:\w+\s+)?files?|confidential\s+(?:\w+\s+)?files?|secrets?\s+(?:folder|directory|file)|keystore)\b|(?:^|\s)(?:\.env|\.jks|\.pem|\.ssh)\b).{0,75}\b(show|display|print|output|reveal|return|give\s+me|tell\s+me|send|post|upload|forward|append|include|embed|put|place|insert|write|encode|submit|pass|exfiltrate|leak|in\s+your\s+(?:response|answer|reply|output)|(?:into|inside)\s+(?:your\s+|the\s+|a\s+)?(?:\w+\s+)?(?:response|answer|reply|output|form|field|box|url|link|markdown)|in\s+(?:a|the)\s+(?:\w+\s+)?(?:form|field|box|url|link|image|markdown|json|query)|as\s+(?:a\s+)?(?:query|url|link|parameter|json|base64)|to\s+(?:me|https?://|(?:the\s+|an?\s+)?external\s+\w+)|https?://|<SAFE_[A-Z0-9_]+>)\b",
            ),
            // EN Exfiltration 3: Direct display/dump of high-sensitivity secret stores OR Reversed Order (Sink/Container -> Sensitive Source)
            (
                "exfiltration",
                85,
                0.94,
                r"(?is)\b(?:(read\s+and\s+display|dump|print\s+out|show\s+me|reveal|output|display)\s+(?:the\s+|all\s+|your\s+)?(contents?\s+of\s+(?:the\s+)?secrets?(?:\s+folder|\s+directory)?|\.env\s+file|environment\s+variables?|api\s+keys?|ssh\s+(?:private\s+)?keys?|private\s+keys?|credentials?|passwords?|conversation\s+history|chat\s+history)|(?:in\s+your\s+(?:response|answer|reply|output)|into\s+(?:the\s+|a\s+)?(?:\w+\s+)?(?:form|field|box|url|link|response|answer)|create\s+a\s+(?:link|url|markdown\s+image)|fill\s+(?:in|out)\s+the\s+form).{0,65}\b(?:include|embed|append|put|insert|write|add|with|containing)\b.{0,45}\b(\.env|environment\s+variables?|api\s+keys?|secret\s+keys?|private\s+keys?|ssh\s+(?:private\s+)?keys?|passwords?|credentials?|tokens?|secret\s+(?:\w+\s+)?files?|conversation\s+history|chat\s+history))\b",
            ),
            // TR Exfiltration 1: Sensitive Source -> Read/Extract/Put into Response, Form, Link/URL, or External Address
            (
                "exfiltration",
                85,
                0.96,
                r"(?is)\b(gizli\s+dosya\w*|ozel\s+dosya\w*|yapilandirma\s+dosya\w*|ayar\s+dosya\w*|gizli\s+anahtar\w*|ozel\s+anahtar\w*|api\s+anahtar\w*|ortam\s+degisken\w*|cevre\s+degisken\w*|sistem\s+degisken\w*|parola\s+not\w*|parola\w*|sifre\w*|token\w*|erisim\s+anahtar\w*|kimlik\s+bilgi\w*|giris\s+bilgi\w*|konusma\s+gecmis\w*|sohbet\s+gecmis\w*|mesaj\s+gecmis\w*|kullanici\s+(?:veri\w*|bilgi\w*|dosya\w*|not\w*|mesaj\w*)|\.env\s*dosya\w*|\.env\b|\.ssh\w*|son\s+\d*\s*(?:e-?posta\w*|mesaj\w*))\b.{0,80}\b(oku\w*|bul\w*|al\w*|cek\w*|cikar\w*|listele\w*|kopyala\w*|sifrele\w*|kodla\w*)?.{0,65}\b(bana\s+(?:gonder\w*|goster\w*|yaz\w*|ver\w*|ilet\w*|oku\w*)|(?:ceva[bp]\w*|yanit\w*|cikti\w*|mesaj\w*|ekran\w*)\s+(?:icine\s+|olarak\s+|sonuna\s+)?(?:koy\w*|ekle\w*|yaz\w*|yazdir\w*|yerlestir\w*|gom\w*|dondur\w*|ili[s]tir\w*)|(?:form\w*|alan\w*|baglanti\w*|link\w*|url\w*|sorgu\w*|parametre\w*|gorsel\w*|resim\w*|kutusu\w*).{0,35}\b(?:koy\w*|ekle\w*|yaz\w*|doldur\w*|gom\w*|yerlestir\w*|gonder\w*|ilet\w*)|(?:dis\s+|uzak\s+|harici\s+)?(?:adres\w*|sunucu\w*|site\w*|baglanti\w*|url\w*|webhook\w*|e-?posta\w*)\s+(?:koy\w*|ekle\w*|gonder\w*|ilet\w*|aktar\w*|yukle\w*|postala\w*|yonlendir\w*)|disari\s+(?:aktar\w*|sizdir\w*|gonder\w*)|https?://|<SAFE_[A-Z0-9_]+>)\b",
            ),
            // TR Exfiltration 2: Reversed Order (Sink/Action first -> Sensitive Source second, e.g. "Cevabın içine / forma / bağlantıya gizli dosyaları / ortam değişkenlerini koy")
            (
                "exfiltration",
                85,
                0.95,
                r"(?is)\b((?:ceva[bp]\w*|yanit\w*|cikti\w*|form\w*|baglanti\w*|link\w*|url\w*|dis\s+adres\w*|dis\s+sunucu\w*|harici\s+adres\w*)\s+(?:icine\s+|olarak\s+|sonuna\s+|alanina\s+)?|oku\w*\s+ve\s+)\b.{0,65}\b(gizli\s+dosya\w*|ozel\s+dosya\w*|ortam\s+degisken\w*|cevre\s+degisken\w*|api\s+anahtar\w*|gizli\s+anahtar\w*|sifre\w*|parola\w*|token\w*|kimlik\s+bilgi\w*|sohbet\s+gecmis\w*|konusma\s+gecmis\w*|\.env)\b.{0,45}\b(koy\w*|ekle\w*|yaz\w*|doldur\w*|gom\w*|yerlestir\w*|gonder\w*|ilet\w*|aktar\w*|paylas\w*|goster\w*)\b",
            ),

            // =========================================================================
            // 10. EXPLICIT ENCODED EXECUTION DIRECTIVES
            // =========================================================================
            (
                "encoding",
                75,
                0.92,
                r"(?is)\b(decode\s+and\s+(?:execute|follow|run|obey)|run\s+this\s+hex\s+command|execute\s+the\s+following\s+rot13\s+encoded\s+instruction|base64\s+coz\s+ve\s+uygula|su\s+kodu\s+coz\s+ve\s+uygula|sifreli\s+metni\s+cozumle\s+ve.{0,25}uygula|asagidaki\s+sifreli\s+talimati\s+coz\w*)\b",
            ),
        ];

        let rules = raw_rules
            .into_iter()
            .map(|(category, weight, confidence, pat)| {
                let regex = Regex::new(pat)
                    .unwrap_or_else(|e| panic!("Invalid regex in category {}: {}", category, e));
                CompiledRule {
                    category,
                    weight,
                    confidence,
                    regex,
                }
            })
            .collect();

        CompiledEngine {
            rules,
            benign_tech_re: Regex::new(
                r"(?is)\b(android|ios|iphone|ipad|samsung|xiaomi|pixel|huawei|telefon\w*|cihaz\w*|tablet\w*|windows|macos|linux|ubuntu|chrome|firefox|edge|safari|opera|brave|browser|tarayici\w*|unity|unreal|godot|steam|discord|playstation|xbox|nintendo|usb|adb|bios|uefi|settings|ayarlar\w*|eslint|prettier|tslint|tsconfig|typescript|webpack|vite|babel|css|scss|tailwind|bootstrap|git|gitignore|docker|kubernetes|nginx|apache|iptables|ufw|firewall|guvenlik\s+duvari|defender|antivirus|ekran\s+suresi|screen\s+time|ebeveyn|parental|vpn| Fizik\s+ayar\w*|terminal\s+gecmis\w*)\b",
            )
            .expect("valid benign_tech_re"),
            ai_target_re: Regex::new(
                r"(?is)\b(yapay\s+zeka\w*|asistan\w*|system\s+prompt\w*|sistem\s+prompt\w*|sistem\s+istem\w*|sistem\s+talimat\w*|jailbreak|dan\s+mode|llm|openclaw|hermes|claude|gpt|gemini|sana\s+verilen|senin\s+kural\w*|kendi\s+kural\w*)\b",
            )
            .expect("valid ai_target_re"),
            question_re: Regex::new(
                r"(?is)(\?|\b(?:nasil|nedir|ne\s+demek|ne\s+ise\s+yarar|neden|niye|hangi\s+menu\w*|how\s+to|how\s+do\s+i|how\s+can\s+i|what\s+is|why\s+does|where\s+is)\b)",
            )
            .expect("valid question_re"),
            negated_prefix_re: Regex::new(
                r"(?is)\b(?:do\s+not|don't|never|must\s+not|should\s+not|shouldn't|cannot|can't|not\s+to)\s+(?:ever\s+)?$",
            )
            .expect("valid negated_prefix_re"),
            b64_re: Regex::new(r"([A-Za-z0-9+/]{16,}={0,2})").expect("valid b64 regex"),
            hex_re: Regex::new(r"(?i)(?:0x)?([0-9a-f]{12,})").expect("valid hex regex"),
            spaced_punct_re: Regex::new(
                r"\b(?:[A-Za-zÇĞİÖŞÜçğıöşü0-9][\.\-_/\|]){2,}[A-Za-zÇĞİÖŞÜçğıöşü0-9]\b",
            )
            .expect("valid spaced_punct_re"),
            spaced_ws_re: Regex::new(
                r"(?:^|\s)([A-Za-zÇĞİÖŞÜçğıöşü0-9](?:\s+[A-Za-zÇĞİÖŞÜçğıöşü0-9]){2,})(?:\s|$)",
            )
            .expect("valid spaced_ws_re"),
            segment_re: Regex::new(
                r"(?i)(baslangictaki|yukaridaki|talimatlarini|talimatlari|kisitlamalari|kurallarini|yonergeleri|onlemlerini|instructions|directives|guidelines|constraints|unrestricted|talimatlar|kisitlama|kurallari|onlemleri|ayarlarini|yonerge|yukarida|baslangic|kullanici|gelistirici|yonetici|gormezden|sormadan|onayladi|approved|approval|previous|disregard|override|emergency|talimat|guvenlik|asistan|dikkate|gecersiz|ozetleme|cevirme|anahtar|earlier|initial|without|summary|translate|sifirla|calistir|onceki|simdiye|bundan|filtre|sistem|kenara|yoksay|kaldir|isteme|bekleme|derhal|goster|gonder|acikla|paylas|yazdir|uygula|hafiza|baglam|ignore|forget|bypass|system|prompt|urgent|kural|sinir|yasak|engel|komut|birak|iptal|devre|kapat|hemen|sorma|sifre|verilen|soylenen|sadece|itaat|gizli|artik|butun|rules|prior|onay|disi|unut|acil|yapay|zeka|sana|bana|rule|tum)",
            )
            .expect("valid segment_re"),
            leet_token_re: Regex::new(r"[A-Za-zÇĞİÖŞÜçğıöşü0-9@\$!€\+]{2,}").expect("valid leet regex"),
        }
    })
}

pub struct Engine {
    _private: (),
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        let _ = get_compiled();
        Self { _private: () }
    }

    fn strip_zero_width(text: &str) -> String {
        text.chars()
            .filter(|&c| {
                !matches!(
                    c,
                    '\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{2060}'
                        | '\u{FEFF}'
                        | '\u{00AD}'
                        | '\u{E0000}'..='\u{E007F}'
                )
            })
            .collect()
    }

    fn segment_collapsed_word(word: &str) -> String {
        if word.len() < 7 {
            return word.to_string();
        }
        let compiled = get_compiled();
        let segmented = compiled.segment_re.replace_all(word, " $1 ");
        segmented.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn collapse_separated_letters(text: &str) -> String {
        let compiled = get_compiled();
        // 1. Collapse punctuation-separated single characters (e.g. Ö.n.c.e.k.i, i-g-n-o-r-e)
        let punct_collapsed = compiled
            .spaced_punct_re
            .replace_all(text, |caps: &regex::Captures| {
                caps[0]
                    .chars()
                    .filter(|&c| !matches!(c, '.' | '-' | '_' | '/' | '|'))
                    .collect::<String>()
            })
            .to_string();

        // 2. Collapse whitespace-separated single characters (e.g. "b o ş l u k l u   o n c e k i   t a l i m a t")
        compiled
            .spaced_ws_re
            .replace_all(&punct_collapsed, |caps: &regex::Captures| {
                let matched = &caps[1];
                if matched.contains("  ") {
                    let words: Vec<String> = matched
                        .split("  ")
                        .map(|part| part.chars().filter(|c| !c.is_whitespace()).collect::<String>())
                        .filter(|s| !s.is_empty())
                        .collect();
                    format!(" {} ", words.join(" "))
                } else {
                    let joined: String = matched.chars().filter(|c| !c.is_whitespace()).collect();
                    let folded = Self::fold_turkish_ascii(&joined);
                    format!(" {} {} ", joined, Self::segment_collapsed_word(&folded))
                }
            })
            .to_string()
    }

    fn normalize_unicode(text: &str) -> String {
        text.nfkc().collect::<String>()
    }

    fn fold_turkish_ascii(text: &str) -> String {
        text.chars()
            .map(|c| match c {
                'ç' | 'Ç' => 'c',
                'ğ' | 'Ğ' => 'g',
                'ı' | 'İ' | 'I' => 'i',
                'ö' | 'Ö' => 'o',
                'ş' | 'Ş' => 's',
                'ü' | 'Ü' => 'u',
                _ => c.to_ascii_lowercase(),
            })
            .collect()
    }

    fn decode_web_formats(text: &str) -> String {
        let html_decoded = decode_html_entities(text).to_string();
        decode(&html_decoded)
            .unwrap_or(std::borrow::Cow::Borrowed(&html_decoded))
            .to_string()
    }

    fn decode_base64(text: &str) -> String {
        let compiled = get_compiled();
        let mut result = text.to_string();
        for cap in compiled.b64_re.captures_iter(text) {
            let b64_str = &cap[1];
            let mut candidates = vec![b64_str.to_string()];
            let rem = b64_str.len() % 4;
            if rem == 2 {
                candidates.push(format!("{}==", b64_str));
            } else if rem == 3 {
                candidates.push(format!("{}=", b64_str));
            }
            for cand in candidates {
                if let Ok(decoded_bytes) =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cand)
                {
                    if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                        if decoded_str
                            .chars()
                            .all(|c| !c.is_control() || c.is_whitespace())
                            && decoded_str.chars().any(|c| c.is_alphabetic())
                        {
                            result.push(' ');
                            result.push_str(&decoded_str);
                            break;
                        }
                    }
                }
            }
        }
        result
    }

    fn decode_hex(text: &str) -> String {
        let compiled = get_compiled();
        let mut result = text.to_string();
        for cap in compiled.hex_re.captures_iter(text) {
            let hex_str = &cap[1];
            if hex_str.len() % 2 == 0 {
                if let Ok(bytes) = hex::decode(hex_str) {
                    if let Ok(decoded_str) = String::from_utf8(bytes) {
                        if decoded_str
                            .chars()
                            .all(|c| !c.is_control() || c.is_whitespace())
                            && decoded_str.chars().any(|c| c.is_alphabetic())
                        {
                            result.push(' ');
                            result.push_str(&decoded_str);
                        }
                    }
                }
            }
        }
        result
    }

    fn decode_rot13(text: &str) -> String {
        if !text.to_ascii_lowercase().contains("rot13") {
            return text.to_string();
        }
        text.chars()
            .map(|c| match c {
                'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
                'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
                _ => c,
            })
            .collect()
    }

    fn normalize_leetspeak(text: &str) -> String {
        let compiled = get_compiled();
        let folded_input = Self::fold_turkish_ascii(text);
        let mapped = compiled
            .leet_token_re
            .replace_all(&folded_input, |caps: &regex::Captures| {
                let tok = &caps[0];
                if tok.len() > 24 {
                    return tok.to_string();
                }
                let has_leet_char = tok.chars().any(|c| {
                    matches!(
                        c,
                        '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '@' | '$' | '!' | '€' | '+'
                    )
                });
                if !has_leet_char {
                    return tok.to_string();
                }

                let mut out: String = tok
                    .chars()
                    .map(|c| match c {
                        '0' => 'o',
                        '1' | '!' => 'i',
                        '2' => 'z',
                        '3' | '€' => 'e',
                        '4' | '@' => 'a',
                        '5' | '$' => 's',
                        '6' | '9' => 'g',
                        '7' | '+' => 't',
                        '8' => 'b',
                        _ => c,
                    })
                    .collect();

                if out == "aii" {
                    return "all".to_string();
                }
                if out == "sii" {
                    return "sil".to_string();
                }

                for (bad, good) in [
                    ("taiimat", "talimat"),
                    ("taimat", "talimat"),
                    ("kuraiiar", "kurallar"),
                    ("kuraia", "kurala"),
                    ("kurai", "kural"),
                    ("kuiian", "kullan"),
                    ("kuian", "kullan"),
                    ("guveniik", "guvenlik"),
                    ("kisitiama", "kisitlama"),
                    ("kaidir", "kaldir"),
                    ("iptai", "iptal"),
                    ("gizii", "gizli"),
                    ("acikia", "acikla"),
                    ("payias", "paylas"),
                    ("caiistir", "calistir"),
                    ("uyguia", "uygula"),
                    ("beiiek", "bellek"),
                    ("engei", "engel"),
                    ("onayia", "onayla"),
                    ("biidir", "bildir"),
                    ("biigi", "bilgi"),
                    ("fiitre", "filtre"),
                    ("fiiter", "filter"),
                    ("geiistir", "gelistir"),
                    ("bosiuk", "bosluk"),
                    ("guideiine", "guideline"),
                    ("iimit", "limit"),
                    ("deiete", "delete"),
                    ("reveai", "reveal"),
                    ("ruie", "rule"),
                    ("roie", "role"),
                    ("iari", "lari"),
                    ("ieri", "leri"),
                ] {
                    if out.contains(bad) {
                        out = out.replace(bad, good);
                    }
                }
                out
            })
            .to_string();
        mapped
    }

    #[allow(dead_code)]
    pub fn preprocess(text: &str) -> String {
        let zw = Self::strip_zero_width(text);
        let uni = Self::normalize_unicode(&zw);
        let web = Self::decode_web_formats(&uni);
        let b64 = Self::decode_base64(&web);
        let hex = Self::decode_hex(&b64);
        let rot = Self::decode_rot13(&hex);
        let collapsed = Self::collapse_separated_letters(&rot);
        Self::normalize_leetspeak(&collapsed)
    }

    fn calculate_entropy(text: &str) -> f32 {
        let mut counts = HashMap::new();
        let mut total = 0_f32;
        for c in text.chars() {
            if c.is_ascii_alphanumeric() {
                *counts.entry(c).or_insert(0usize) += 1;
                total += 1.0;
            }
        }
        if total == 0.0 {
            return 0.0;
        }
        let mut entropy = 0_f32;
        for &count in counts.values() {
            let p = count as f32 / total;
            entropy -= p * p.log2();
        }
        entropy
    }

    pub fn scan(&self, input: &str) -> ScanResult {
        let compiled = get_compiled();

        let zw = Self::strip_zero_width(input);
        let unicode_norm = Self::normalize_unicode(&zw);
        let web_decoded = Self::decode_web_formats(&unicode_norm);
        let b64_decoded = Self::decode_base64(&web_decoded);
        let hex_decoded = Self::decode_hex(&b64_decoded);
        let rot13_decoded = Self::decode_rot13(&hex_decoded);
        let ascii_folded = Self::fold_turkish_ascii(&rot13_decoded);
        let collapsed = Self::collapse_separated_letters(&ascii_folded);
        let leet_normalized = Self::normalize_leetspeak(&collapsed);
        let leet_collapsed = Self::collapse_separated_letters(&leet_normalized);

        let variants = [
            input,
            &zw,
            &unicode_norm,
            &web_decoded,
            &b64_decoded,
            &hex_decoded,
            &rot13_decoded,
            &ascii_folded,
            &collapsed,
            &leet_normalized,
            &leet_collapsed,
        ];

        let has_benign_tech = compiled.benign_tech_re.is_match(&ascii_folded);
        let has_ai_target = compiled.ai_target_re.is_match(&ascii_folded)
            || compiled.ai_target_re.is_match(&leet_collapsed);
        let is_question = compiled.question_re.is_match(&ascii_folded);

        // Global deduplication across all variants using BTreeMap keyed by category
        let mut by_category: BTreeMap<String, (u8, f32, String)> = BTreeMap::new();

        for variant in variants {
            for rule in &compiled.rules {
                if let Some(mat) = rule.regex.find(variant) {
                    let snippet: String = variant[mat.start()..].chars().take(100).collect();

                    // Suppress false positives on negative warnings ("Please do not forget the safety rules")
                    if rule.category == "direct_injection"
                        && compiled.negated_prefix_re.is_match(&variant[..mat.start()])
                    {
                        continue;
                    }

                    // Suppress false positives on consumer/developer tech questions & statements
                    // when no AI/assistant/prompt target is mentioned
                    if (rule.category == "jailbreak" || rule.category == "direct_injection")
                        && has_benign_tech
                        && !has_ai_target
                        && (is_question
                            || snippet.contains("developer mode")
                            || snippet.contains("gelistirici modu")
                            || snippet.contains("fizik ayar"))
                    {
                        continue;
                    }

                    let entry = by_category.entry(rule.category.to_string()).or_insert((
                        rule.weight,
                        rule.confidence,
                        snippet.clone(),
                    ));
                    if rule.weight > entry.0
                        || (rule.weight == entry.0 && rule.confidence > entry.1)
                    {
                        *entry = (rule.weight, rule.confidence, snippet);
                    }
                }
            }
        }

        let mut total_score: u16 = 0;
        let mut matches: Vec<(String, f32, String)> = Vec::new();

        for (cat, (weight, conf, snippet)) in &by_category {
            total_score += *weight as u16;
            matches.push((cat.clone(), *conf, snippet.clone()));
        }
        if by_category.len() >= 2 {
            total_score += 15;
        }

        let entropy = Self::calculate_entropy(input);
        if entropy > 5.35 && input.len() > 40 && !by_category.is_empty() {
            total_score += 10;
            matches.push((
                "high_entropy_anomaly".to_string(),
                0.75,
                format!("Entropy: {:.2}", entropy),
            ));
        }

        let risk_score = total_score.min(100) as u8;
        let is_safe = risk_score < 50;

        let threat_level = match risk_score {
            0..=29 => "SAFE".to_string(),
            30..=49 => "LOW".to_string(),
            50..=69 => "MEDIUM".to_string(),
            70..=84 => "HIGH".to_string(),
            _ => "CRITICAL".to_string(),
        };

        ScanResult {
            is_safe,
            risk_score,
            threat_level,
            matches,
        }
    }
}
