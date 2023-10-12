pub mod language {
    use serde::{Deserialize, Serialize};

    /// This enum defines the available languages.
    #[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize, Hash)]
    pub enum Language {
        /// English (default language).
        EN,
        /// Italian.
        IT,
        /// French.
        FR,
        /// Spanish.
        ES,
        /// Polish.
        PL,
        /// German,
        DE,
        /// Ukrainian
        UK,
        /// Simplified Chinese
        ZH,
        /// Romanian
        RO,
        /// Korean
        KO,
        /// Portuguese
        PT,
        /// Turkish
        TR,
        /// Russian
        RU,
        /// Greek
        EL,
        // /// Persian
        // FA,
        /// Swedish
        SV,
        /// Finnish
        FI,
        /// Japanese
        JA,
    }

    impl Default for Language {
        fn default() -> Self {
            Self::EN
        }
    }

    impl Language {
        pub(crate) const ROW1: [Language; 1] = [Language::EN];
        pub(crate) const ROW2: [Language; 4] =
            [Language::DE, Language::EL, Language::ES, Language::FI];
        pub(crate) const ROW3: [Language; 4] =
            [Language::FR, Language::IT, Language::JA, Language::KO];
        pub(crate) const ROW4: [Language; 4] =
            [Language::PL, Language::PT, Language::RO, Language::RU];
        pub(crate) const ROW5: [Language; 4] =
            [Language::SV, Language::TR, Language::UK, Language::ZH];

        pub fn get_radio_label(&self) -> &str {
            match self {
                Language::EN => "English",
                Language::IT => "Italiano",
                Language::FR => "Français",
                Language::ES => "Español",
                Language::PL => "Polski",
                Language::DE => "Deutsch",
                Language::UK => "Українська",
                Language::ZH => "简体中文",
                Language::RO => "Română",
                Language::KO => "한국어",
                Language::TR => "Türkçe",
                Language::RU => "Русский",
                Language::PT => "Português",
                Language::EL => "Ελληνικά",
                // Language::FA => "فارسی",
                Language::SV => "Svenska",
                Language::FI => "Suomi",
                Language::JA => "日本語",
            }
        }
    }

    pub fn both_translation(language: Language) -> &'static str {
        match language {
            Language::EN => "both",
            Language::IT => "entrambi",
            Language::FR => "les deux",
            Language::ES | Language::PT => "ambos",
            Language::PL => "oba",
            Language::DE => "beide",
            Language::UK => "обидва",
            Language::ZH => "皆需",
            Language::RO => "ambele",
            Language::KO => "둘다",
            Language::TR => "ikiside",
            Language::RU => "оба",
            Language::EL => "αμφότερα",
            // Language::FA => "هر دو",
            Language::SV => "båda",
            Language::FI => "molemmat",
            Language::JA => "両方",
        }
    }
}
