import { useState, useRef, useEffect, createContext, useContext } from "react";

// ─── 📦 Install: npm install firebase @emailjs/browser ───────────────────
// import { initializeApp } from "firebase/app";
// import { getAuth, RecaptchaVerifier, signInWithPhoneNumber } from "firebase/auth";
// import emailjs from "@emailjs/browser";
//
// ─── 🔧 YOUR CREDENTIALS (fill these in) ────────────────────────────────
const FIREBASE_CONFIG = {
  apiKey:            "YOUR_FIREBASE_API_KEY",
  authDomain:        "YOUR_PROJECT_ID.firebaseapp.com",
  projectId:         "YOUR_PROJECT_ID",
  storageBucket:     "YOUR_PROJECT_ID.appspot.com",
  messagingSenderId: "YOUR_SENDER_ID",
  appId:             "YOUR_APP_ID",
};
// Firebase Console → Authentication → Sign-in method → Enable "Phone"
// Firebase Console → Authentication → Settings → Add localhost to Authorized domains

const EMAILJS_CONFIG = {
  serviceId:  "YOUR_EMAILJS_SERVICE_ID",    // emailjs.com → Email Services
  templateId: "YOUR_EMAILJS_TEMPLATE_ID",   // emailjs.com → Email Templates
  publicKey:  "YOUR_EMAILJS_PUBLIC_KEY",    // emailjs.com → Account → API Keys
};
// EmailJS template must have these variables: {{to_email}} {{otp_code}} {{app_name}}
// ─────────────────────────────────────────────────────────────────────────

// ── Firebase & EmailJS live instances (uncomment after npm install) ───────
// const firebaseApp  = initializeApp(FIREBASE_CONFIG);
// const firebaseAuth = getAuth(firebaseApp);
// emailjs.init(EMAILJS_CONFIG.publicKey);

// ── DEMO MODE (remove when real credentials added) ────────────────────────
const DEMO_MODE = true; // set false after adding real credentials

const COLORS = {
  yellow: "#FFD600", green: "#00C853", red: "#FF1744", blue: "#2979FF",
  dark: "#0A0A0A", card: "#111111", text: "#FFFFFF", muted: "#666666",
};
const ACCENTS = [COLORS.yellow, COLORS.green, COLORS.red, COLORS.blue];
let postIdCtr = 20;

const LANGS = {
  en: { name: "English", flag: "🇬🇧", dir: "ltr" },
  hi: { name: "हिंदी", flag: "🇮🇳", dir: "ltr" },
  es: { name: "Español", flag: "🇪🇸", dir: "ltr" },
  fr: { name: "Français", flag: "🇫🇷", dir: "ltr" },
  ar: { name: "العربية", flag: "🇸🇦", dir: "rtl" },
  pt: { name: "Português", flag: "🇧🇷", dir: "ltr" },
  zh: { name: "中文", flag: "🇨🇳", dir: "ltr" },
  ja: { name: "日本語", flag: "🇯🇵", dir: "ltr" },
  ko: { name: "한국어", flag: "🇰🇷", dir: "ltr" },
  de: { name: "Deutsch", flag: "🇩🇪", dir: "ltr" },
  ru: { name: "Русский", flag: "🇷🇺", dir: "ltr" },
  tr: { name: "Türkçe", flag: "🇹🇷", dir: "ltr" },
  id: { name: "Indonesia", flag: "🇮🇩", dir: "ltr" },
  sw: { name: "Kiswahili", flag: "🇰🇪", dir: "ltr" },
  bn: { name: "বাংলা", flag: "🇧🇩", dir: "ltr" },
};

const T = {
  en: {
    tagline: "Connect with the world. Post away.",
    whatsOnMind: "What's on your mind?",
    postNow: "POST NOW →",
    joinWorld: "JOIN POST WORLD →",
    copyLink: "🔗 COPY LINK",
    linkCopied: "✓ LINK COPIED!",
    cancel: "Cancel",
    save: "SAVE ✓",
    send: "SEND",
    edit: "EDIT",
    connect: "CONNECT",
    accept: "ACCEPT",
    decline: "DECLINE",
    pending: "PENDING ✕",
    friend: "✓ FRIEND",
    newPost: "NEW POST",
    color: "Color",
    nameStar: "Name *",
    handle: "Handle",
    location: "📍 Location",
    about: "📝 About",
    avatarColor: "Avatar color:",
    choosePhotoColor: "Choose photo or color:",
    removePhoto: "Remove Photo ✕",
    yourName: "Your name",
    aboutPlaceholder: "Tell us about yourself...",
    writeComment: "Write a comment...",
    searchPlaceholder: "Search posts, users, location...",
    discoverPeople: "DISCOVER PEOPLE 🌍",
    yourFriends: "YOUR FRIENDS 🤝",
    connRequests: "CONNECTION REQUESTS 📬",
    inviteFriends: "INVITE YOUR FRIENDS 🚀",
    shareVia: "SHARE VIA",
    inviteByName: "INVITE BY NAME",
    friendName: "Friend's name...",
    enterFriendName: "Enter your friend's name and send an invite:",
    firstComment: "Be the first to comment!",
    noFriendsYet: "No friends yet.",
    goToDiscover: "Go to Discover and connect!",
    noPendingReq: "No pending requests.",
    noPostsYet: "No posts yet. Create your first post! 🚀",
    nothingFound: "Nothing found 😢",
    inviteYourFriends: "Invite your friends!",
    shareInviteLink: "Share your invite link — they'll connect with you directly.",
    linkCopiedToast: "Invite link copied! 🔗",
    reqCancelled: "Request cancelled.",
    reqDeclined: "Request declined.",
    isNowFriend: "is now your friend!",
    inviteSent: "Invite sent to",
    connectReqSent: "Connect request sent to",
    noPostsProfile: "No posts yet. Post something! 🚀",
    home: "Home",
    explore: "Explore",
    friends: "Friends",
    profile: "Profile",
    discover: "Discover",
    requests: "Requests",
    invite: "Invite",
    posts: "POSTS",
    likes: "LIKES",
    friendsCount: "FRIENDS",
    shareWA: "Share on WhatsApp",
    shareTwitter: "Share on Twitter / X",
    shareSMS: "Send via Message / SMS",
    wantsToConnect: "wants to connect with you on Post!",
    profileEdit: "✏️ PROFILE EDIT",
    cityCountry: "City, Country (optional)",
    usernameOpt: "@username (optional)",
    username: "@username",
    justNow: "Just now",
    post: "POST",
    all: "All 🌍",
    asia: "Asia 🌏",
    europe: "Europe 🌍",
    americas: "Americas 🌎",
    africa: "Africa 🌍",
    oceania: "Oceania 🌊",
    langPicker: "Choose Language",
    username_opt: "@username (optional)"
  },
  hi: {
    tagline: "दुनिया से जुड़ो। पोस्ट करो।",
    whatsOnMind: "क्या शेयर करना चाहते हो?",
    postNow: "पोस्ट करो →",
    joinWorld: "पोस्ट वर्ल्ड में आ जाओ →",
    copyLink: "🔗 लिंक कॉपी करो",
    linkCopied: "✓ लिंक कॉपी हो गया!",
    cancel: "रद्द करें",
    save: "सेव करें ✓",
    send: "भेजें",
    edit: "संपादित करें",
    connect: "जुड़ें",
    accept: "स्वीकार करें",
    decline: "अस्वीकार करें",
    pending: "लंबित ✕",
    friend: "✓ दोस्त",
    newPost: "नई पोस्ट",
    color: "रंग",
    nameStar: "नाम *",
    handle: "हैंडल",
    location: "📍 स्थान",
    about: "📝 परिचय",
    avatarColor: "अवतार रंग:",
    choosePhotoColor: "फ़ोटो या रंग चुनें:",
    removePhoto: "फ़ोटो हटाएं ✕",
    yourName: "आपका नाम",
    aboutPlaceholder: "अपने बारे में बताएं...",
    writeComment: "टिप्पणी लिखें...",
    searchPlaceholder: "पोस्ट, उपयोगकर्ता, स्थान खोजें...",
    discoverPeople: "लोगों को खोजें 🌍",
    yourFriends: "आपके दोस्त 🤝",
    connRequests: "कनेक्शन अनुरोध 📬",
    inviteFriends: "दोस्तों को आमंत्रित करें 🚀",
    shareVia: "शेयर करें",
    inviteByName: "नाम से आमंत्रित करें",
    friendName: "दोस्त का नाम...",
    enterFriendName: "दोस्त का नाम लिखें और आमंत्रण भेजें:",
    firstComment: "पहले टिप्पणी करें!",
    noFriendsYet: "अभी कोई दोस्त नहीं।",
    goToDiscover: "खोज टैब पर जाएं और जुड़ें!",
    noPendingReq: "कोई लंबित अनुरोध नहीं।",
    noPostsYet: "अभी कोई पोस्ट नहीं। पहली पोस्ट करें! 🚀",
    nothingFound: "कुछ नहीं मिला 😢",
    inviteYourFriends: "अपने दोस्तों को बुलाएं!",
    shareInviteLink: "आमंत्रण लिंक शेयर करें — वे सीधे आपसे जुड़ेंगे।",
    linkCopiedToast: "आमंत्रण लिंक कॉपी हो गया! 🔗",
    reqCancelled: "अनुरोध रद्द।",
    reqDeclined: "अनुरोध अस्वीकार।",
    isNowFriend: "अब आपके दोस्त हैं!",
    inviteSent: "आमंत्रण भेजा",
    connectReqSent: "कनेक्शन अनुरोध भेजा",
    noPostsProfile: "अभी कोई पोस्ट नहीं। कुछ पोस्ट करें! 🚀",
    home: "होम",
    explore: "खोजें",
    friends: "दोस्त",
    profile: "प्रोफ़ाइल",
    discover: "खोजें",
    requests: "अनुरोध",
    invite: "आमंत्रित करें",
    posts: "पोस्ट",
    likes: "लाइक",
    friendsCount: "दोस्त",
    shareWA: "WhatsApp पर शेयर",
    shareTwitter: "Twitter / X पर शेयर",
    shareSMS: "SMS/मैसेज भेजें",
    wantsToConnect: "आपसे पोस्ट पर जुड़ना चाहता है!",
    profileEdit: "✏️ प्रोफ़ाइल संपादित करें",
    cityCountry: "शहर, देश (वैकल्पिक)",
    usernameOpt: "@उपयोगकर्ता (वैकल्पिक)",
    username: "@उपयोगकर्ता",
    justNow: "अभी",
    post: "पोस्ट",
    all: "सभी 🌍",
    asia: "एशिया 🌏",
    europe: "यूरोप 🌍",
    americas: "अमेरिका 🌎",
    africa: "अफ्रीका 🌍",
    oceania: "ओशिनिया 🌊",
    langPicker: "भाषा चुनें",
    username_opt: "@उपयोगकर्ता (वैकल्पिक)"
  },
  es: {
    tagline: "Conecta con el mundo. Publica ya.",
    whatsOnMind: "¿Qué quieres compartir?",
    postNow: "PUBLICAR →",
    joinWorld: "ÚNETE AL MUNDO POST →",
    copyLink: "🔗 COPIAR ENLACE",
    linkCopied: "✓ ¡ENLACE COPIADO!",
    cancel: "Cancelar",
    save: "GUARDAR ✓",
    send: "ENVIAR",
    edit: "EDITAR",
    connect: "CONECTAR",
    accept: "ACEPTAR",
    decline: "RECHAZAR",
    pending: "PENDIENTE ✕",
    friend: "✓ AMIGO",
    newPost: "NUEVA PUBLICACIÓN",
    color: "Color",
    nameStar: "Nombre *",
    handle: "Usuario",
    location: "📍 Ubicación",
    about: "📝 Sobre mí",
    avatarColor: "Color de avatar:",
    choosePhotoColor: "Elige foto o color:",
    removePhoto: "Quitar foto ✕",
    yourName: "Tu nombre",
    aboutPlaceholder: "Cuéntanos sobre ti...",
    writeComment: "Escribe un comentario...",
    searchPlaceholder: "Buscar posts, usuarios, ubicación...",
    discoverPeople: "DESCUBRIR PERSONAS 🌍",
    yourFriends: "TUS AMIGOS 🤝",
    connRequests: "SOLICITUDES DE CONEXIÓN 📬",
    inviteFriends: "INVITAR AMIGOS 🚀",
    shareVia: "COMPARTIR VÍA",
    inviteByName: "INVITAR POR NOMBRE",
    friendName: "Nombre del amigo...",
    enterFriendName: "Escribe el nombre de tu amigo:",
    firstComment: "¡Sé el primero en comentar!",
    noFriendsYet: "Aún sin amigos.",
    goToDiscover: "¡Ve a Descubrir y conéctate!",
    noPendingReq: "No hay solicitudes pendientes.",
    noPostsYet: "Sin publicaciones. ¡Crea la primera! 🚀",
    nothingFound: "Nada encontrado 😢",
    inviteYourFriends: "¡Invita a tus amigos!",
    shareInviteLink: "Comparte tu enlace — se conectarán directamente.",
    linkCopiedToast: "¡Enlace de invitación copiado! 🔗",
    reqCancelled: "Solicitud cancelada.",
    reqDeclined: "Solicitud rechazada.",
    isNowFriend: "¡ahora es tu amigo!",
    inviteSent: "Invitación enviada a",
    connectReqSent: "Solicitud enviada a",
    noPostsProfile: "Sin publicaciones. ¡Publica algo! 🚀",
    home: "Inicio",
    explore: "Explorar",
    friends: "Amigos",
    profile: "Perfil",
    discover: "Descubrir",
    requests: "Solicitudes",
    invite: "Invitar",
    posts: "POSTS",
    likes: "LIKES",
    friendsCount: "AMIGOS",
    shareWA: "Compartir en WhatsApp",
    shareTwitter: "Compartir en Twitter / X",
    shareSMS: "Enviar por SMS",
    wantsToConnect: "quiere conectarse contigo en Post!",
    profileEdit: "✏️ EDITAR PERFIL",
    cityCountry: "Ciudad, País (opcional)",
    usernameOpt: "@usuario (opcional)",
    username: "@usuario",
    justNow: "Ahora",
    post: "POST",
    all: "Todos 🌍",
    asia: "Asia 🌏",
    europe: "Europa 🌍",
    americas: "Américas 🌎",
    africa: "África 🌍",
    oceania: "Oceanía 🌊",
    langPicker: "Elegir idioma",
    username_opt: "@usuario (opcional)"
  },
  fr: {
    tagline: "Connecte-toi au monde. Publie.",
    whatsOnMind: "Que veux-tu partager?",
    postNow: "PUBLIER →",
    joinWorld: "REJOINS LE MONDE POST →",
    copyLink: "🔗 COPIER LE LIEN",
    linkCopied: "✓ LIEN COPIÉ!",
    cancel: "Annuler",
    save: "SAUVEGARDER ✓",
    send: "ENVOYER",
    edit: "MODIFIER",
    connect: "CONNECTER",
    accept: "ACCEPTER",
    decline: "REFUSER",
    pending: "EN ATTENTE ✕",
    friend: "✓ AMI",
    newPost: "NOUVELLE PUBLICATION",
    color: "Couleur",
    nameStar: "Nom *",
    handle: "Identifiant",
    location: "📍 Lieu",
    about: "📝 À propos",
    avatarColor: "Couleur avatar:",
    choosePhotoColor: "Choisir photo ou couleur:",
    removePhoto: "Supprimer la photo ✕",
    yourName: "Ton nom",
    aboutPlaceholder: "Parle-nous de toi...",
    writeComment: "Écrire un commentaire...",
    searchPlaceholder: "Rechercher posts, utilisateurs, lieux...",
    discoverPeople: "DÉCOUVRIR DES GENS 🌍",
    yourFriends: "TES AMIS 🤝",
    connRequests: "DEMANDES DE CONNEXION 📬",
    inviteFriends: "INVITER DES AMIS 🚀",
    shareVia: "PARTAGER VIA",
    inviteByName: "INVITER PAR NOM",
    friendName: "Nom de l'ami...",
    enterFriendName: "Entre le nom de ton ami:",
    firstComment: "Sois le premier à commenter!",
    noFriendsYet: "Pas encore d'amis.",
    goToDiscover: "Va dans Découvrir et connecte-toi!",
    noPendingReq: "Aucune demande en attente.",
    noPostsYet: "Aucune publication. Crée la première! 🚀",
    nothingFound: "Rien trouvé 😢",
    inviteYourFriends: "Invite tes amis!",
    shareInviteLink: "Partage ton lien d'invitation.",
    linkCopiedToast: "Lien d'invitation copié! 🔗",
    reqCancelled: "Demande annulée.",
    reqDeclined: "Demande refusée.",
    isNowFriend: "est maintenant ton ami!",
    inviteSent: "Invitation envoyée à",
    connectReqSent: "Demande envoyée à",
    noPostsProfile: "Aucune publication. Publie quelque chose! 🚀",
    home: "Accueil",
    explore: "Explorer",
    friends: "Amis",
    profile: "Profil",
    discover: "Découvrir",
    requests: "Demandes",
    invite: "Inviter",
    posts: "POSTS",
    likes: "LIKES",
    friendsCount: "AMIS",
    shareWA: "Partager sur WhatsApp",
    shareTwitter: "Partager sur Twitter / X",
    shareSMS: "Envoyer par SMS",
    wantsToConnect: "veut se connecter avec toi sur Post!",
    profileEdit: "✏️ MODIFIER PROFIL",
    cityCountry: "Ville, Pays (optionnel)",
    usernameOpt: "@utilisateur (optionnel)",
    username: "@utilisateur",
    justNow: "Maintenant",
    post: "POST",
    all: "Tous 🌍",
    asia: "Asie 🌏",
    europe: "Europe 🌍",
    americas: "Amériques 🌎",
    africa: "Afrique 🌍",
    oceania: "Océanie 🌊",
    langPicker: "Choisir la langue",
    username_opt: "@utilisateur (optionnel)"
  },
  ar: {
    tagline: "تواصل مع العالم. انشر.",
    whatsOnMind: "ما الذي تريد مشاركته؟",
    postNow: "انشر الآن →",
    joinWorld: "انضم إلى عالم بوست →",
    copyLink: "🔗 نسخ الرابط",
    linkCopied: "✓ تم نسخ الرابط!",
    cancel: "إلغاء",
    save: "حفظ ✓",
    send: "إرسال",
    edit: "تعديل",
    connect: "تواصل",
    accept: "قبول",
    decline: "رفض",
    pending: "قيد الانتظار ✕",
    friend: "✓ صديق",
    newPost: "منشور جديد",
    color: "اللون",
    nameStar: "الاسم *",
    handle: "المعرف",
    location: "📍 الموقع",
    about: "📝 نبذة",
    avatarColor: "لون الصورة:",
    choosePhotoColor: "اختر صورة أو لون:",
    removePhoto: "إزالة الصورة ✕",
    yourName: "اسمك",
    aboutPlaceholder: "أخبرنا عن نفسك...",
    writeComment: "اكتب تعليقاً...",
    searchPlaceholder: "ابحث عن منشورات، مستخدمين...",
    discoverPeople: "اكتشف الناس 🌍",
    yourFriends: "أصدقاؤك 🤝",
    connRequests: "طلبات التواصل 📬",
    inviteFriends: "دعوة الأصدقاء 🚀",
    shareVia: "شارك عبر",
    inviteByName: "دعوة بالاسم",
    friendName: "اسم الصديق...",
    enterFriendName: "أدخل اسم صديقك وأرسل دعوة:",
    firstComment: "كن أول من يعلق!",
    noFriendsYet: "لا أصدقاء بعد.",
    goToDiscover: "اذهب إلى الاستكشاف وتواصل!",
    noPendingReq: "لا طلبات معلقة.",
    noPostsYet: "لا منشورات. أنشئ أول منشور! 🚀",
    nothingFound: "لم يُعثر على شيء 😢",
    inviteYourFriends: "ادعُ أصدقاءك!",
    shareInviteLink: "شارك رابط الدعوة.",
    linkCopiedToast: "تم نسخ رابط الدعوة! 🔗",
    reqCancelled: "تم إلغاء الطلب.",
    reqDeclined: "تم رفض الطلب.",
    isNowFriend: "أصبح صديقك الآن!",
    inviteSent: "تم إرسال الدعوة إلى",
    connectReqSent: "تم إرسال طلب التواصل إلى",
    noPostsProfile: "لا منشورات. انشر شيئاً! 🚀",
    home: "الرئيسية",
    explore: "استكشف",
    friends: "الأصدقاء",
    profile: "الملف",
    discover: "اكتشف",
    requests: "الطلبات",
    invite: "دعوة",
    posts: "المنشورات",
    likes: "الإعجابات",
    friendsCount: "الأصدقاء",
    shareWA: "شارك على واتساب",
    shareTwitter: "شارك على تويتر / X",
    shareSMS: "إرسال عبر الرسائل",
    wantsToConnect: "يريد التواصل معك على بوست!",
    profileEdit: "✏️ تعديل الملف",
    cityCountry: "المدينة، الدولة (اختياري)",
    usernameOpt: "@المستخدم (اختياري)",
    username: "@المستخدم",
    justNow: "الآن",
    post: "منشور",
    all: "الكل 🌍",
    asia: "آسيا 🌏",
    europe: "أوروبا 🌍",
    americas: "الأمريكيتان 🌎",
    africa: "أفريقيا 🌍",
    oceania: "أوقيانوسيا 🌊",
    langPicker: "اختر اللغة",
    username_opt: "@المستخدم (اختياري)"
  },
  pt: {
    tagline: "Conecte-se ao mundo. Publique.",
    whatsOnMind: "O que você quer compartilhar?",
    postNow: "PUBLICAR →",
    joinWorld: "ENTRAR NO MUNDO POST →",
    copyLink: "🔗 COPIAR LINK",
    linkCopied: "✓ LINK COPIADO!",
    cancel: "Cancelar",
    save: "SALVAR ✓",
    send: "ENVIAR",
    edit: "EDITAR",
    connect: "CONECTAR",
    accept: "ACEITAR",
    decline: "RECUSAR",
    pending: "PENDENTE ✕",
    friend: "✓ AMIGO",
    newPost: "NOVA PUBLICAÇÃO",
    color: "Cor",
    nameStar: "Nome *",
    handle: "Usuário",
    location: "📍 Localização",
    about: "📝 Sobre mim",
    avatarColor: "Cor do avatar:",
    choosePhotoColor: "Escolha foto ou cor:",
    removePhoto: "Remover foto ✕",
    yourName: "Seu nome",
    aboutPlaceholder: "Conte sobre você...",
    writeComment: "Escreva um comentário...",
    searchPlaceholder: "Buscar posts, usuários, local...",
    discoverPeople: "DESCOBRIR PESSOAS 🌍",
    yourFriends: "SEUS AMIGOS 🤝",
    connRequests: "PEDIDOS DE CONEXÃO 📬",
    inviteFriends: "CONVIDAR AMIGOS 🚀",
    shareVia: "COMPARTILHAR VIA",
    inviteByName: "CONVIDAR POR NOME",
    friendName: "Nome do amigo...",
    enterFriendName: "Digite o nome do seu amigo:",
    firstComment: "Seja o primeiro a comentar!",
    noFriendsYet: "Sem amigos ainda.",
    goToDiscover: "Vá em Descobrir e conecte-se!",
    noPendingReq: "Nenhum pedido pendente.",
    noPostsYet: "Sem posts ainda. Crie o primeiro! 🚀",
    nothingFound: "Nada encontrado 😢",
    inviteYourFriends: "Convide seus amigos!",
    shareInviteLink: "Compartilhe seu link de convite.",
    linkCopiedToast: "Link de convite copiado! 🔗",
    reqCancelled: "Pedido cancelado.",
    reqDeclined: "Pedido recusado.",
    isNowFriend: "agora é seu amigo!",
    inviteSent: "Convite enviado para",
    connectReqSent: "Pedido enviado para",
    noPostsProfile: "Sem posts. Publique algo! 🚀",
    home: "Início",
    explore: "Explorar",
    friends: "Amigos",
    profile: "Perfil",
    discover: "Descobrir",
    requests: "Pedidos",
    invite: "Convidar",
    posts: "POSTS",
    likes: "LIKES",
    friendsCount: "AMIGOS",
    shareWA: "Compartilhar no WhatsApp",
    shareTwitter: "Compartilhar no Twitter / X",
    shareSMS: "Enviar por SMS",
    wantsToConnect: "quer se conectar com você no Post!",
    profileEdit: "✏️ EDITAR PERFIL",
    cityCountry: "Cidade, País (opcional)",
    usernameOpt: "@usuario (opcional)",
    username: "@usuario",
    justNow: "Agora",
    post: "POST",
    all: "Todos 🌍",
    asia: "Ásia 🌏",
    europe: "Europa 🌍",
    americas: "Américas 🌎",
    africa: "África 🌍",
    oceania: "Oceania 🌊",
    langPicker: "Escolher idioma",
    username_opt: "@usuario (opcional)"
  },
  zh: {
    tagline: "与世界连接。发帖吧。",
    whatsOnMind: "你想分享什么？",
    postNow: "发帖 →",
    joinWorld: "加入POST世界 →",
    copyLink: "🔗 复制链接",
    linkCopied: "✓ 链接已复制！",
    cancel: "取消",
    save: "保存 ✓",
    send: "发送",
    edit: "编辑",
    connect: "连接",
    accept: "接受",
    decline: "拒绝",
    pending: "待处理 ✕",
    friend: "✓ 好友",
    newPost: "新帖子",
    color: "颜色",
    nameStar: "姓名 *",
    handle: "用户名",
    location: "📍 地点",
    about: "📝 简介",
    avatarColor: "头像颜色：",
    choosePhotoColor: "选择照片或颜色：",
    removePhoto: "删除照片 ✕",
    yourName: "你的名字",
    aboutPlaceholder: "介绍一下你自己...",
    writeComment: "写评论...",
    searchPlaceholder: "搜索帖子、用户、地点...",
    discoverPeople: "发现朋友 🌍",
    yourFriends: "我的好友 🤝",
    connRequests: "连接请求 📬",
    inviteFriends: "邀请好友 🚀",
    shareVia: "通过以下方式分享",
    inviteByName: "按名字邀请",
    friendName: "好友姓名...",
    enterFriendName: "输入好友姓名并发送邀请：",
    firstComment: "成为第一个评论的人！",
    noFriendsYet: "还没有好友。",
    goToDiscover: "去发现标签添加好友！",
    noPendingReq: "没有待处理的请求。",
    noPostsYet: "还没有帖子。发第一帖！ 🚀",
    nothingFound: "没有找到 😢",
    inviteYourFriends: "邀请你的朋友！",
    shareInviteLink: "分享邀请链接，他们将直接与你连接。",
    linkCopiedToast: "邀请链接已复制！ 🔗",
    reqCancelled: "请求已取消。",
    reqDeclined: "请求已拒绝。",
    isNowFriend: "现在是你的好友了！",
    inviteSent: "邀请已发送给",
    connectReqSent: "连接请求已发送给",
    noPostsProfile: "还没有帖子。发点什么！ 🚀",
    home: "首页",
    explore: "探索",
    friends: "好友",
    profile: "我的",
    discover: "发现",
    requests: "请求",
    invite: "邀请",
    posts: "帖子",
    likes: "点赞",
    friendsCount: "好友",
    shareWA: "在WhatsApp上分享",
    shareTwitter: "在Twitter / X上分享",
    shareSMS: "发送短信",
    wantsToConnect: "想在POST上与你连接！",
    profileEdit: "✏️ 编辑资料",
    cityCountry: "城市，国家（可选）",
    usernameOpt: "@用户名（可选）",
    username: "@用户名",
    justNow: "刚刚",
    post: "帖子",
    all: "全部 🌍",
    asia: "亚洲 🌏",
    europe: "欧洲 🌍",
    americas: "美洲 🌎",
    africa: "非洲 🌍",
    oceania: "大洋洲 🌊",
    langPicker: "选择语言",
    username_opt: "@用户名（可选）"
  },
  ja: {
    tagline: "世界とつながろう。投稿しよう。",
    whatsOnMind: "何をシェアしますか？",
    postNow: "投稿する →",
    joinWorld: "POSTの世界に参加 →",
    copyLink: "🔗 リンクをコピー",
    linkCopied: "✓ コピーしました！",
    cancel: "キャンセル",
    save: "保存 ✓",
    send: "送信",
    edit: "編集",
    connect: "つながる",
    accept: "承認",
    decline: "拒否",
    pending: "保留中 ✕",
    friend: "✓ フレンド",
    newPost: "新しい投稿",
    color: "カラー",
    nameStar: "名前 *",
    handle: "ハンドル",
    location: "📍 場所",
    about: "📝 自己紹介",
    avatarColor: "アバターカラー：",
    choosePhotoColor: "写真またはカラーを選択：",
    removePhoto: "写真を削除 ✕",
    yourName: "あなたの名前",
    aboutPlaceholder: "自己紹介を入力...",
    writeComment: "コメントを書く...",
    searchPlaceholder: "投稿、ユーザー、場所を検索...",
    discoverPeople: "ユーザーを探す 🌍",
    yourFriends: "フレンド 🤝",
    connRequests: "フレンドリクエスト 📬",
    inviteFriends: "フレンドを招待 🚀",
    shareVia: "シェア",
    inviteByName: "名前で招待",
    friendName: "フレンドの名前...",
    enterFriendName: "フレンドの名前を入力して招待：",
    firstComment: "最初にコメントしよう！",
    noFriendsYet: "まだフレンドがいません。",
    goToDiscover: "探すタブでつながろう！",
    noPendingReq: "保留中のリクエストはありません。",
    noPostsYet: "まだ投稿がありません。最初の投稿を！ 🚀",
    nothingFound: "見つかりませんでした 😢",
    inviteYourFriends: "フレンドを招待しよう！",
    shareInviteLink: "招待リンクをシェアしよう。",
    linkCopiedToast: "招待リンクをコピーしました！ 🔗",
    reqCancelled: "リクエストをキャンセルしました。",
    reqDeclined: "リクエストを拒否しました。",
    isNowFriend: "がフレンドになりました！",
    inviteSent: "に招待を送りました",
    connectReqSent: "にリクエストを送りました",
    noPostsProfile: "まだ投稿なし。投稿しよう！ 🚀",
    home: "ホーム",
    explore: "探す",
    friends: "フレンド",
    profile: "プロフィール",
    discover: "探す",
    requests: "リクエスト",
    invite: "招待",
    posts: "投稿",
    likes: "いいね",
    friendsCount: "フレンド",
    shareWA: "WhatsAppでシェア",
    shareTwitter: "Twitter / Xでシェア",
    shareSMS: "SMSで送る",
    wantsToConnect: "さんがPOSTでつながりたいです！",
    profileEdit: "✏️ プロフィール編集",
    cityCountry: "都市、国（任意）",
    usernameOpt: "@ユーザー名（任意）",
    username: "@ユーザー名",
    justNow: "たった今",
    post: "投稿",
    all: "すべて 🌍",
    asia: "アジア 🌏",
    europe: "ヨーロッパ 🌍",
    americas: "アメリカ 🌎",
    africa: "アフリカ 🌍",
    oceania: "オセアニア 🌊",
    langPicker: "言語を選ぶ",
    username_opt: "@ユーザー名（任意）"
  },
  ko: {
    tagline: "세계와 연결하세요. 지금 포스트!",
    whatsOnMind: "무엇을 공유하고 싶으신가요?",
    postNow: "포스트하기 →",
    joinWorld: "POST 세계에 참여하기 →",
    copyLink: "🔗 링크 복사",
    linkCopied: "✓ 링크 복사됨!",
    cancel: "취소",
    save: "저장 ✓",
    send: "보내기",
    edit: "편집",
    connect: "연결",
    accept: "수락",
    decline: "거절",
    pending: "대기 중 ✕",
    friend: "✓ 친구",
    newPost: "새 포스트",
    color: "색상",
    nameStar: "이름 *",
    handle: "핸들",
    location: "📍 위치",
    about: "📝 소개",
    avatarColor: "아바타 색상:",
    choosePhotoColor: "사진 또는 색상 선택:",
    removePhoto: "사진 삭제 ✕",
    yourName: "이름 입력",
    aboutPlaceholder: "자신을 소개해 주세요...",
    writeComment: "댓글 작성...",
    searchPlaceholder: "포스트, 사용자, 위치 검색...",
    discoverPeople: "사람 찾기 🌍",
    yourFriends: "내 친구 🤝",
    connRequests: "연결 요청 📬",
    inviteFriends: "친구 초대 🚀",
    shareVia: "공유하기",
    inviteByName: "이름으로 초대",
    friendName: "친구 이름...",
    enterFriendName: "친구 이름을 입력하고 초대장 보내기:",
    firstComment: "첫 번째 댓글을 달아보세요!",
    noFriendsYet: "아직 친구가 없어요.",
    goToDiscover: "찾기 탭에서 연결하세요!",
    noPendingReq: "대기 중인 요청 없음.",
    noPostsYet: "포스트가 없습니다. 첫 포스트를! 🚀",
    nothingFound: "찾을 수 없음 😢",
    inviteYourFriends: "친구를 초대해보세요!",
    shareInviteLink: "초대 링크를 공유하세요.",
    linkCopiedToast: "초대 링크가 복사됨! 🔗",
    reqCancelled: "요청 취소됨.",
    reqDeclined: "요청 거절됨.",
    isNowFriend: "님이 친구가 됐습니다!",
    inviteSent: "에게 초대장 보냄",
    connectReqSent: "에게 요청 보냄",
    noPostsProfile: "포스트 없음. 공유하세요! 🚀",
    home: "홈",
    explore: "탐색",
    friends: "친구",
    profile: "프로필",
    discover: "찾기",
    requests: "요청",
    invite: "초대",
    posts: "포스트",
    likes: "좋아요",
    friendsCount: "친구",
    shareWA: "WhatsApp으로 공유",
    shareTwitter: "Twitter / X로 공유",
    shareSMS: "SMS로 보내기",
    wantsToConnect: "님이 POST에서 연결을 원합니다!",
    profileEdit: "✏️ 프로필 편집",
    cityCountry: "도시, 국가 (선택)",
    usernameOpt: "@사용자 (선택)",
    username: "@사용자",
    justNow: "방금",
    post: "포스트",
    all: "전체 🌍",
    asia: "아시아 🌏",
    europe: "유럽 🌍",
    americas: "아메리카 🌎",
    africa: "아프리카 🌍",
    oceania: "오세아니아 🌊",
    langPicker: "언어 선택",
    username_opt: "@사용자 (선택)"
  },
  de: {
    tagline: "Verbinde dich mit der Welt. Poste jetzt.",
    whatsOnMind: "Was möchtest du teilen?",
    postNow: "POSTEN →",
    joinWorld: "DER POST-WELT BEITRETEN →",
    copyLink: "🔗 LINK KOPIEREN",
    linkCopied: "✓ LINK KOPIERT!",
    cancel: "Abbrechen",
    save: "SPEICHERN ✓",
    send: "SENDEN",
    edit: "BEARBEITEN",
    connect: "VERBINDEN",
    accept: "ANNEHMEN",
    decline: "ABLEHNEN",
    pending: "AUSSTEHEND ✕",
    friend: "✓ FREUND",
    newPost: "NEUER POST",
    color: "Farbe",
    nameStar: "Name *",
    handle: "Benutzername",
    location: "📍 Standort",
    about: "📝 Über mich",
    avatarColor: "Avatar-Farbe:",
    choosePhotoColor: "Foto oder Farbe wählen:",
    removePhoto: "Foto entfernen ✕",
    yourName: "Dein Name",
    aboutPlaceholder: "Erzähl uns von dir...",
    writeComment: "Kommentar schreiben...",
    searchPlaceholder: "Posts, Nutzer, Orte suchen...",
    discoverPeople: "LEUTE ENTDECKEN 🌍",
    yourFriends: "DEINE FREUNDE 🤝",
    connRequests: "VERBINDUNGSANFRAGEN 📬",
    inviteFriends: "FREUNDE EINLADEN 🚀",
    shareVia: "TEILEN VIA",
    inviteByName: "PER NAME EINLADEN",
    friendName: "Name des Freundes...",
    enterFriendName: "Name des Freundes eingeben:",
    firstComment: "Sei der Erste, der kommentiert!",
    noFriendsYet: "Noch keine Freunde.",
    goToDiscover: "Gehe zu Entdecken und verbinde dich!",
    noPendingReq: "Keine ausstehenden Anfragen.",
    noPostsYet: "Noch keine Posts. Erstelle den ersten! 🚀",
    nothingFound: "Nichts gefunden 😢",
    inviteYourFriends: "Lade Freunde ein!",
    shareInviteLink: "Teile deinen Einladungslink.",
    linkCopiedToast: "Einladungslink kopiert! 🔗",
    reqCancelled: "Anfrage abgebrochen.",
    reqDeclined: "Anfrage abgelehnt.",
    isNowFriend: "ist jetzt dein Freund!",
    inviteSent: "Einladung gesendet an",
    connectReqSent: "Anfrage gesendet an",
    noPostsProfile: "Keine Posts. Poste etwas! 🚀",
    home: "Start",
    explore: "Entdecken",
    friends: "Freunde",
    profile: "Profil",
    discover: "Entdecken",
    requests: "Anfragen",
    invite: "Einladen",
    posts: "POSTS",
    likes: "LIKES",
    friendsCount: "FREUNDE",
    shareWA: "Auf WhatsApp teilen",
    shareTwitter: "Auf Twitter / X teilen",
    shareSMS: "Per SMS senden",
    wantsToConnect: "möchte sich auf Post mit dir verbinden!",
    profileEdit: "✏️ PROFIL BEARBEITEN",
    cityCountry: "Stadt, Land (optional)",
    usernameOpt: "@Benutzername (optional)",
    username: "@Benutzername",
    justNow: "Jetzt",
    post: "POST",
    all: "Alle 🌍",
    asia: "Asien 🌏",
    europe: "Europa 🌍",
    americas: "Amerika 🌎",
    africa: "Afrika 🌍",
    oceania: "Ozeanien 🌊",
    langPicker: "Sprache wählen",
    username_opt: "@Benutzername (optional)"
  },
  ru: {
    tagline: "Связывайся с миром. Публикуй.",
    whatsOnMind: "Что ты хочешь поделиться?",
    postNow: "ОПУБЛИКОВАТЬ →",
    joinWorld: "ПРИСОЕДИНИТЬСЯ К POST →",
    copyLink: "🔗 КОПИРОВАТЬ ССЫЛКУ",
    linkCopied: "✓ ССЫЛКА СКОПИРОВАНА!",
    cancel: "Отмена",
    save: "СОХРАНИТЬ ✓",
    send: "ОТПРАВИТЬ",
    edit: "РЕДАКТИРОВАТЬ",
    connect: "ПОДКЛЮЧИТЬСЯ",
    accept: "ПРИНЯТЬ",
    decline: "ОТКЛОНИТЬ",
    pending: "ОЖИДАНИЕ ✕",
    friend: "✓ ДРУГ",
    newPost: "НОВЫЙ ПОСТ",
    color: "Цвет",
    nameStar: "Имя *",
    handle: "Логин",
    location: "📍 Местоположение",
    about: "📝 О себе",
    avatarColor: "Цвет аватара:",
    choosePhotoColor: "Выбери фото или цвет:",
    removePhoto: "Убрать фото ✕",
    yourName: "Твоё имя",
    aboutPlaceholder: "Расскажи о себе...",
    writeComment: "Написать комментарий...",
    searchPlaceholder: "Поиск постов, пользователей, мест...",
    discoverPeople: "НАЙТИ ЛЮДЕЙ 🌍",
    yourFriends: "ТВОИ ДРУЗЬЯ 🤝",
    connRequests: "ЗАПРОСЫ НА СВЯЗЬ 📬",
    inviteFriends: "ПРИГЛАСИТЬ ДРУЗЕЙ 🚀",
    shareVia: "ПОДЕЛИТЬСЯ ЧЕРЕЗ",
    inviteByName: "ПРИГЛАСИТЬ ПО ИМЕНИ",
    friendName: "Имя друга...",
    enterFriendName: "Введи имя друга и отправь приглашение:",
    firstComment: "Будь первым, кто прокомментирует!",
    noFriendsYet: "Пока нет друзей.",
    goToDiscover: "Перейди в Найти и подключись!",
    noPendingReq: "Нет ожидающих запросов.",
    noPostsYet: "Ещё нет постов. Создай первый! 🚀",
    nothingFound: "Ничего не найдено 😢",
    inviteYourFriends: "Пригласи друзей!",
    shareInviteLink: "Поделись ссылкой-приглашением.",
    linkCopiedToast: "Ссылка скопирована! 🔗",
    reqCancelled: "Запрос отменён.",
    reqDeclined: "Запрос отклонён.",
    isNowFriend: "теперь твой друг!",
    inviteSent: "Приглашение отправлено",
    connectReqSent: "Запрос отправлен",
    noPostsProfile: "Нет постов. Опубликуй что-нибудь! 🚀",
    home: "Главная",
    explore: "Поиск",
    friends: "Друзья",
    profile: "Профиль",
    discover: "Найти",
    requests: "Запросы",
    invite: "Пригласить",
    posts: "ПОСТЫ",
    likes: "ЛАЙКИ",
    friendsCount: "ДРУЗЬЯ",
    shareWA: "Поделиться в WhatsApp",
    shareTwitter: "Поделиться в Twitter / X",
    shareSMS: "Отправить SMS",
    wantsToConnect: "хочет подключиться к тебе в Post!",
    profileEdit: "✏️ РЕДАКТИРОВАТЬ ПРОФИЛЬ",
    cityCountry: "Город, Страна (необязательно)",
    usernameOpt: "@имя_пользователя (необязательно)",
    username: "@имя_пользователя",
    justNow: "Только что",
    post: "ПОСТ",
    all: "Все 🌍",
    asia: "Азия 🌏",
    europe: "Европа 🌍",
    americas: "Америка 🌎",
    africa: "Африка 🌍",
    oceania: "Океания 🌊",
    langPicker: "Выбор языка",
    username_opt: "@имя_пользователя (необязательно)"
  },
  tr: {
    tagline: "Dünyayla bağlan. Paylaş.",
    whatsOnMind: "Ne paylaşmak istiyorsun?",
    postNow: "PAYLAŞ →",
    joinWorld: "POST DÜNYASINA KATIL →",
    copyLink: "🔗 BAĞLANTIYI KOPYALA",
    linkCopied: "✓ BAĞLANTI KOPYALANDI!",
    cancel: "İptal",
    save: "KAYDET ✓",
    send: "GÖNDER",
    edit: "DÜZENLE",
    connect: "BAĞLAN",
    accept: "KABUL ET",
    decline: "REDDET",
    pending: "BEKLEMEDE ✕",
    friend: "✓ ARKADAŞ",
    newPost: "YENİ GÖNDERİ",
    color: "Renk",
    nameStar: "Ad *",
    handle: "Kullanıcı Adı",
    location: "📍 Konum",
    about: "📝 Hakkımda",
    avatarColor: "Avatar rengi:",
    choosePhotoColor: "Fotoğraf veya renk seç:",
    removePhoto: "Fotoğrafı kaldır ✕",
    yourName: "Adın",
    aboutPlaceholder: "Kendinden bahset...",
    writeComment: "Yorum yaz...",
    searchPlaceholder: "Gönderi, kullanıcı, konum ara...",
    discoverPeople: "KİŞİLERİ KEŞFET 🌍",
    yourFriends: "ARKADAŞLARIN 🤝",
    connRequests: "BAĞLANTI İSTEKLERİ 📬",
    inviteFriends: "ARKADAŞLARI DAVET ET 🚀",
    shareVia: "PAYLAŞ",
    inviteByName: "ADLA DAVET ET",
    friendName: "Arkadaşın adı...",
    enterFriendName: "Arkadaşının adını gir ve davet gönder:",
    firstComment: "İlk yorumu sen yap!",
    noFriendsYet: "Henüz arkadaş yok.",
    goToDiscover: "Keşfet'e git ve bağlan!",
    noPendingReq: "Bekleyen istek yok.",
    noPostsYet: "Henüz gönderi yok. İlkini oluştur! 🚀",
    nothingFound: "Bulunamadı 😢",
    inviteYourFriends: "Arkadaşlarını davet et!",
    shareInviteLink: "Davet bağlantını paylaş.",
    linkCopiedToast: "Davet bağlantısı kopyalandı! 🔗",
    reqCancelled: "İstek iptal edildi.",
    reqDeclined: "İstek reddedildi.",
    isNowFriend: "artık arkadaşın!",
    inviteSent: "Davet gönderildi:",
    connectReqSent: "İstek gönderildi:",
    noPostsProfile: "Gönderi yok. Bir şeyler paylaş! 🚀",
    home: "Anasayfa",
    explore: "Keşfet",
    friends: "Arkadaşlar",
    profile: "Profil",
    discover: "Keşfet",
    requests: "İstekler",
    invite: "Davet",
    posts: "GÖNDERİ",
    likes: "BEĞENİ",
    friendsCount: "ARKADAŞ",
    shareWA: "WhatsApp'ta paylaş",
    shareTwitter: "Twitter / X'te paylaş",
    shareSMS: "SMS ile gönder",
    wantsToConnect: "sana Post'ta bağlanmak istiyor!",
    profileEdit: "✏️ PROFİLİ DÜZENLE",
    cityCountry: "Şehir, Ülke (isteğe bağlı)",
    usernameOpt: "@kullaniciadi (isteğe bağlı)",
    username: "@kullaniciadi",
    justNow: "Şimdi",
    post: "GÖNDERİ",
    all: "Tümü 🌍",
    asia: "Asya 🌏",
    europe: "Avrupa 🌍",
    americas: "Amerika 🌎",
    africa: "Afrika 🌍",
    oceania: "Okyanusya 🌊",
    langPicker: "Dil Seç",
    username_opt: "@kullaniciadi (isteğe bağlı)"
  },
  id: {
    tagline: "Terhubung dengan dunia. Posting sekarang.",
    whatsOnMind: "Apa yang ingin kamu bagikan?",
    postNow: "POSTING →",
    joinWorld: "BERGABUNG KE DUNIA POST →",
    copyLink: "🔗 SALIN TAUTAN",
    linkCopied: "✓ TAUTAN DISALIN!",
    cancel: "Batal",
    save: "SIMPAN ✓",
    send: "KIRIM",
    edit: "EDIT",
    connect: "HUBUNGKAN",
    accept: "TERIMA",
    decline: "TOLAK",
    pending: "TERTUNDA ✕",
    friend: "✓ TEMAN",
    newPost: "POSTING BARU",
    color: "Warna",
    nameStar: "Nama *",
    handle: "Nama Pengguna",
    location: "📍 Lokasi",
    about: "📝 Tentang",
    avatarColor: "Warna avatar:",
    choosePhotoColor: "Pilih foto atau warna:",
    removePhoto: "Hapus foto ✕",
    yourName: "Nama kamu",
    aboutPlaceholder: "Ceritakan tentang dirimu...",
    writeComment: "Tulis komentar...",
    searchPlaceholder: "Cari posting, pengguna, lokasi...",
    discoverPeople: "TEMUKAN ORANG 🌍",
    yourFriends: "TEMANMU 🤝",
    connRequests: "PERMINTAAN KONEKSI 📬",
    inviteFriends: "UNDANG TEMAN 🚀",
    shareVia: "BAGIKAN VIA",
    inviteByName: "UNDANG DENGAN NAMA",
    friendName: "Nama teman...",
    enterFriendName: "Masukkan nama temanmu dan kirim undangan:",
    firstComment: "Jadilah yang pertama berkomentar!",
    noFriendsYet: "Belum ada teman.",
    goToDiscover: "Pergi ke Temukan dan terhubung!",
    noPendingReq: "Tidak ada permintaan tertunda.",
    noPostsYet: "Belum ada posting. Buat yang pertama! 🚀",
    nothingFound: "Tidak ditemukan 😢",
    inviteYourFriends: "Undang temanmu!",
    shareInviteLink: "Bagikan tautan undanganmu.",
    linkCopiedToast: "Tautan undangan disalin! 🔗",
    reqCancelled: "Permintaan dibatalkan.",
    reqDeclined: "Permintaan ditolak.",
    isNowFriend: "sekarang temanmu!",
    inviteSent: "Undangan dikirim ke",
    connectReqSent: "Permintaan dikirim ke",
    noPostsProfile: "Belum ada posting. Posting sesuatu! 🚀",
    home: "Beranda",
    explore: "Jelajahi",
    friends: "Teman",
    profile: "Profil",
    discover: "Temukan",
    requests: "Permintaan",
    invite: "Undang",
    posts: "POSTING",
    likes: "SUKA",
    friendsCount: "TEMAN",
    shareWA: "Bagikan di WhatsApp",
    shareTwitter: "Bagikan di Twitter / X",
    shareSMS: "Kirim via SMS",
    wantsToConnect: "ingin terhubung denganmu di Post!",
    profileEdit: "✏️ EDIT PROFIL",
    cityCountry: "Kota, Negara (opsional)",
    usernameOpt: "@pengguna (opsional)",
    username: "@pengguna",
    justNow: "Baru saja",
    post: "POST",
    all: "Semua 🌍",
    asia: "Asia 🌏",
    europe: "Eropa 🌍",
    americas: "Amerika 🌎",
    africa: "Afrika 🌍",
    oceania: "Oseania 🌊",
    langPicker: "Pilih Bahasa",
    username_opt: "@pengguna (opsional)"
  },
  sw: {
    tagline: "Unganika na dunia. Chapisha.",
    whatsOnMind: "Unataka kushiriki nini?",
    postNow: "CHAPISHA →",
    joinWorld: "JIUNGE NA DUNIA YA POST →",
    copyLink: "🔗 NAKILI KIUNGO",
    linkCopied: "✓ KIUNGO KIMENAKILIWA!",
    cancel: "Ghairi",
    save: "HIFADHI ✓",
    send: "TUMA",
    edit: "HARIRI",
    connect: "UNGANA",
    accept: "KUBALI",
    decline: "KATAA",
    pending: "INASUBIRI ✕",
    friend: "✓ RAFIKI",
    newPost: "CHAPISHO JIPYA",
    color: "Rangi",
    nameStar: "Jina *",
    handle: "Jina la Mtumiaji",
    location: "📍 Mahali",
    about: "📝 Kuhusu",
    avatarColor: "Rangi ya picha:",
    choosePhotoColor: "Chagua picha au rangi:",
    removePhoto: "Ondoa picha ✕",
    yourName: "Jina lako",
    aboutPlaceholder: "Tuambie kuhusu wewe...",
    writeComment: "Andika maoni...",
    searchPlaceholder: "Tafuta machapisho, watumiaji, mahali...",
    discoverPeople: "GUNDUA WATU 🌍",
    yourFriends: "MARAFIKI WAKO 🤝",
    connRequests: "MAOMBI YA MUUNGANISHO 📬",
    inviteFriends: "ALIKA MARAFIKI 🚀",
    shareVia: "SHIRIKI KUPITIA",
    inviteByName: "ALIKA KWA JINA",
    friendName: "Jina la rafiki...",
    enterFriendName: "Ingiza jina la rafiki wako na tuma mwaliko:",
    firstComment: "Kuwa wa kwanza kutoa maoni!",
    noFriendsYet: "Bado hakuna marafiki.",
    goToDiscover: "Nenda kwa Gundua na ungana!",
    noPendingReq: "Hakuna maombi yanayosubiri.",
    noPostsYet: "Bado hakuna machapisho. Unda la kwanza! 🚀",
    nothingFound: "Hakuna kilichopatikana 😢",
    inviteYourFriends: "Alika marafiki wako!",
    shareInviteLink: "Shiriki kiungo chako cha mwaliko.",
    linkCopiedToast: "Kiungo cha mwaliko kimenakiliwa! 🔗",
    reqCancelled: "Ombi limeghairiwa.",
    reqDeclined: "Ombi limekataliwa.",
    isNowFriend: "ni rafiki wako sasa!",
    inviteSent: "Mwaliko umetumwa kwa",
    connectReqSent: "Ombi limetumwa kwa",
    noPostsProfile: "Hakuna machapisho. Chapisha kitu! 🚀",
    home: "Nyumbani",
    explore: "Chunguza",
    friends: "Marafiki",
    profile: "Wasifu",
    discover: "Gundua",
    requests: "Maombi",
    invite: "Alika",
    posts: "MACHAPISHO",
    likes: "MAPENDEZI",
    friendsCount: "MARAFIKI",
    shareWA: "Shiriki kwenye WhatsApp",
    shareTwitter: "Shiriki kwenye Twitter / X",
    shareSMS: "Tuma SMS",
    wantsToConnect: "anataka kukuunganika kwenye Post!",
    profileEdit: "✏️ HARIRI WASIFU",
    cityCountry: "Mji, Nchi (hiari)",
    usernameOpt: "@mtumiaji (hiari)",
    username: "@mtumiaji",
    justNow: "Sasa hivi",
    post: "CHAPISHO",
    all: "Yote 🌍",
    asia: "Asia 🌏",
    europe: "Ulaya 🌍",
    americas: "Amerika 🌎",
    africa: "Afrika 🌍",
    oceania: "Oceania 🌊",
    langPicker: "Chagua Lugha",
    username_opt: "@mtumiaji (hiari)"
  },
  bn: {
    tagline: "বিশ্বের সাথে সংযুক্ত হন। পোস্ট করুন।",
    whatsOnMind: "আপনি কী শেয়ার করতে চান?",
    postNow: "পোস্ট করুন →",
    joinWorld: "পোস্ট বিশ্বে যোগ দিন →",
    copyLink: "🔗 লিংক কপি করুন",
    linkCopied: "✓ লিংক কপি হয়েছে!",
    cancel: "বাতিল",
    save: "সংরক্ষণ ✓",
    send: "পাঠান",
    edit: "সম্পাদনা",
    connect: "সংযুক্ত হন",
    accept: "গ্রহণ করুন",
    decline: "প্রত্যাখ্যান করুন",
    pending: "অপেক্ষমাণ ✕",
    friend: "✓ বন্ধু",
    newPost: "নতুন পোস্ট",
    color: "রঙ",
    nameStar: "নাম *",
    handle: "হ্যান্ডেল",
    location: "📍 অবস্থান",
    about: "📝 পরিচয়",
    avatarColor: "অবতার রঙ:",
    choosePhotoColor: "ছবি বা রঙ বেছে নিন:",
    removePhoto: "ছবি সরান ✕",
    yourName: "আপনার নাম",
    aboutPlaceholder: "নিজের পরিচয় দিন...",
    writeComment: "মন্তব্য লিখুন...",
    searchPlaceholder: "পোস্ট, ব্যবহারকারী, অবস্থান খুঁজুন...",
    discoverPeople: "মানুষ খুঁজুন 🌍",
    yourFriends: "আপনার বন্ধুরা 🤝",
    connRequests: "সংযোগের অনুরোধ 📬",
    inviteFriends: "বন্ধুদের আমন্ত্রণ করুন 🚀",
    shareVia: "শেয়ার করুন",
    inviteByName: "নাম দিয়ে আমন্ত্রণ",
    friendName: "বন্ধুর নাম...",
    enterFriendName: "বন্ধুর নাম লিখুন এবং আমন্ত্রণ পাঠান:",
    firstComment: "প্রথম মন্তব্য করুন!",
    noFriendsYet: "এখনো কোনো বন্ধু নেই।",
    goToDiscover: "আবিষ্কার ট্যাবে যান!",
    noPendingReq: "কোনো অপেক্ষমাণ অনুরোধ নেই।",
    noPostsYet: "এখনো কোনো পোস্ট নেই। প্রথম পোস্ট করুন! 🚀",
    nothingFound: "কিছু পাওয়া যায়নি 😢",
    inviteYourFriends: "বন্ধুদের আমন্ত্রণ করুন!",
    shareInviteLink: "আমন্ত্রণ লিংক শেয়ার করুন।",
    linkCopiedToast: "আমন্ত্রণ লিংক কপি হয়েছে! 🔗",
    reqCancelled: "অনুরোধ বাতিল।",
    reqDeclined: "অনুরোধ প্রত্যাখ্যাত।",
    isNowFriend: "এখন আপনার বন্ধু!",
    inviteSent: "আমন্ত্রণ পাঠানো হয়েছে",
    connectReqSent: "অনুরোধ পাঠানো হয়েছে",
    noPostsProfile: "কোনো পোস্ট নেই। শেয়ার করুন! 🚀",
    home: "হোম",
    explore: "অন্বেষণ",
    friends: "বন্ধু",
    profile: "প্রোফাইল",
    discover: "আবিষ্কার",
    requests: "অনুরোধ",
    invite: "আমন্ত্রণ",
    posts: "পোস্ট",
    likes: "পছন্দ",
    friendsCount: "বন্ধু",
    shareWA: "WhatsApp-এ শেয়ার করুন",
    shareTwitter: "Twitter / X-এ শেয়ার করুন",
    shareSMS: "SMS পাঠান",
    wantsToConnect: "আপনার সাথে Post-এ সংযুক্ত হতে চান!",
    profileEdit: "✏️ প্রোফাইল সম্পাদনা",
    cityCountry: "শহর, দেশ (ঐচ্ছিক)",
    usernameOpt: "@ব্যবহারকারী (ঐচ্ছিক)",
    username: "@ব্যবহারকারী",
    justNow: "এইমাত্র",
    post: "পোস্ট",
    all: "সব 🌍",
    asia: "এশিয়া 🌏",
    europe: "ইউরোপ 🌍",
    americas: "আমেরিকা 🌎",
    africa: "আফ্রিকা 🌍",
    oceania: "ওশেনিয়া 🌊",
    langPicker: "ভাষা বেছে নিন",
    username_opt: "@ব্যবহারকারী (ঐচ্ছিক)"
  }
};

const WORLD_USERS = [
  { id: "u1", name: "Aryan", handle: "@aryan_world", location: "Mumbai, India", about: "Photographer & traveller 📷", continent: "Asia", flag: "🇮🇳", avatar: { photo: null, bg: "#FFD600", letter: "A" } },
  { id: "u4", name: "Divya", handle: "@divya_india", location: "Delhi, India", about: "Coder & foodie 🍕", continent: "Asia", flag: "🇮🇳", avatar: { photo: null, bg: "#FF1744", letter: "D" } },
  { id: "u5", name: "Emre", handle: "@emre_ist", location: "Istanbul, Turkey", about: "Music producer 🎧", continent: "Asia", flag: "🇹🇷", avatar: { photo: null, bg: "#FFD600", letter: "E" } },
  { id: "u6", name: "Fatima", handle: "@fatima_sa", location: "Riyadh, Saudi Arabia", about: "Writer & poet ✍️", continent: "Asia", flag: "🇸🇦", avatar: { photo: null, bg: "#00C853", letter: "F" } },
  { id: "u7", name: "Wei", handle: "@wei_cn", location: "Beijing, China", about: "AI researcher 🤖", continent: "Asia", flag: "🇨🇳", avatar: { photo: null, bg: "#2979FF", letter: "W" } },
  { id: "u8", name: "Yuki", handle: "@yuki_jp", location: "Tokyo, Japan", about: "Manga artist 🎨", continent: "Asia", flag: "🇯🇵", avatar: { photo: null, bg: "#00C853", letter: "Y" } },
  { id: "u9", name: "Soo-Jin", handle: "@soojin_kr", location: "Seoul, South Korea", about: "K-pop enthusiast 🎵", continent: "Asia", flag: "🇰🇷", avatar: { photo: null, bg: "#FF1744", letter: "S" } },
  { id: "u10", name: "Budi", handle: "@budi_id", location: "Jakarta, Indonesia", about: "Surfer 🏄", continent: "Asia", flag: "🇮🇩", avatar: { photo: null, bg: "#FFD600", letter: "B" } },
  { id: "u11", name: "Kiri", handle: "@kiri_th", location: "Bangkok, Thailand", about: "Street food chef 🍜", continent: "Asia", flag: "🇹🇭", avatar: { photo: null, bg: "#2979FF", letter: "K" } },
  { id: "u12", name: "Nguyen", handle: "@nguyen_vn", location: "Ho Chi Minh, Vietnam", about: "Entrepreneur 🚀", continent: "Asia", flag: "🇻🇳", avatar: { photo: null, bg: "#00C853", letter: "N" } },
  { id: "u13", name: "Ana", handle: "@ana_ph", location: "Manila, Philippines", about: "Nurse & blogger 💊", continent: "Asia", flag: "🇵🇭", avatar: { photo: null, bg: "#FF1744", letter: "A" } },
  { id: "u14", name: "Rahim", handle: "@rahim_bd", location: "Dhaka, Bangladesh", about: "Teacher 📚", continent: "Asia", flag: "🇧🇩", avatar: { photo: null, bg: "#2979FF", letter: "R" } },
  { id: "u15", name: "Mei", handle: "@mei_sg", location: "Singapore City, Singapore", about: "Finance & tech 💹", continent: "Asia", flag: "🇸🇬", avatar: { photo: null, bg: "#FFD600", letter: "M" } },
  { id: "u16", name: "Tariq", handle: "@tariq_pk", location: "Karachi, Pakistan", about: "Civil engineer ⚙️", continent: "Asia", flag: "🇵🇰", avatar: { photo: null, bg: "#00C853", letter: "T" } },
  { id: "u17", name: "David", handle: "@david_il", location: "Tel Aviv, Israel", about: "Software developer 💻", continent: "Asia", flag: "🇮🇱", avatar: { photo: null, bg: "#FF1744", letter: "D" } },
  { id: "u18", name: "Ahmad", handle: "@ahmad_jo", location: "Amman, Jordan", about: "Journalist 📰", continent: "Asia", flag: "🇯🇴", avatar: { photo: null, bg: "#2979FF", letter: "A" } },
  { id: "u19", name: "Leila", handle: "@leila_ir", location: "Tehran, Iran", about: "Scientist 🔬", continent: "Asia", flag: "🇮🇷", avatar: { photo: null, bg: "#FFD600", letter: "L" } },
  { id: "u20", name: "Hana", handle: "@hana_lb", location: "Beirut, Lebanon", about: "Architect 🏛️", continent: "Asia", flag: "🇱🇧", avatar: { photo: null, bg: "#00C853", letter: "H" } },
  { id: "u21", name: "Temur", handle: "@temur_kz", location: "Almaty, Kazakhstan", about: "Athlete 🏊", continent: "Asia", flag: "🇰🇿", avatar: { photo: null, bg: "#FF1744", letter: "T" } },
  { id: "u22", name: "Bayar", handle: "@bayar_mn", location: "Ulaanbaatar, Mongolia", about: "Horse rider 🐴", continent: "Asia", flag: "🇲🇳", avatar: { photo: null, bg: "#2979FF", letter: "B" } },
  { id: "u23", name: "Kimsan", handle: "@kimsan_kh", location: "Phnom Penh, Cambodia", about: "Tourism guide 🏯", continent: "Asia", flag: "🇰🇭", avatar: { photo: null, bg: "#FFD600", letter: "K" } },
  { id: "u24", name: "Phyo", handle: "@phyo_mm", location: "Yangon, Myanmar", about: "Graphic designer 🎨", continent: "Asia", flag: "🇲🇲", avatar: { photo: null, bg: "#00C853", letter: "P" } },
  { id: "u25", name: "Priya", handle: "@priya_lk", location: "Colombo, Sri Lanka", about: "Tea farmer ☕", continent: "Asia", flag: "🇱🇰", avatar: { photo: null, bg: "#FF1744", letter: "P" } },
  { id: "u26", name: "Omar", handle: "@omar_ae", location: "Dubai, UAE", about: "Business consultant 🏢", continent: "Asia", flag: "🇦🇪", avatar: { photo: null, bg: "#2979FF", letter: "O" } },
  { id: "u27", name: "Suresh", handle: "@suresh_np", location: "Kathmandu, Nepal", about: "Mountain guide 🏔️", continent: "Asia", flag: "🇳🇵", avatar: { photo: null, bg: "#FFD600", letter: "S" } },
  { id: "u28", name: "Ngan", handle: "@ngan_la", location: "Vientiane, Laos", about: "Rice farmer 🌾", continent: "Asia", flag: "🇱🇦", avatar: { photo: null, bg: "#00C853", letter: "N" } },
  { id: "u2", name: "Bella", handle: "@bella_creates", location: "London, UK", about: "Designer. Coffee lover ☕", continent: "Europe", flag: "🇬🇧", avatar: { photo: null, bg: "#00C853", letter: "B" } },
  { id: "u29", name: "Pierre", handle: "@pierre_fr", location: "Paris, France", about: "Chef & food blogger 🥐", continent: "Europe", flag: "🇫🇷", avatar: { photo: null, bg: "#FF1744", letter: "P" } },
  { id: "u30", name: "Hans", handle: "@hans_de", location: "Berlin, Germany", about: "Musician 🎹", continent: "Europe", flag: "🇩🇪", avatar: { photo: null, bg: "#2979FF", letter: "H" } },
  { id: "u31", name: "Sofia", handle: "@sofia_it", location: "Rome, Italy", about: "Fashion designer 👗", continent: "Europe", flag: "🇮🇹", avatar: { photo: null, bg: "#FFD600", letter: "S" } },
  { id: "u32", name: "Diego", handle: "@diego_es", location: "Barcelona, Spain", about: "Football fan ⚽", continent: "Europe", flag: "🇪🇸", avatar: { photo: null, bg: "#00C853", letter: "D" } },
  { id: "u33", name: "Ana", handle: "@ana_pt", location: "Lisbon, Portugal", about: "Surfer & traveller 🏄", continent: "Europe", flag: "🇵🇹", avatar: { photo: null, bg: "#FF1744", letter: "A" } },
  { id: "u34", name: "Anna", handle: "@anna_se", location: "Stockholm, Sweden", about: "Environmentalist 🌿", continent: "Europe", flag: "🇸🇪", avatar: { photo: null, bg: "#2979FF", letter: "A" } },
  { id: "u35", name: "Ivan", handle: "@ivan_ru", location: "Moscow, Russia", about: "Chess grandmaster ♟️", continent: "Europe", flag: "🇷🇺", avatar: { photo: null, bg: "#FFD600", letter: "I" } },
  { id: "u36", name: "Marta", handle: "@marta_pl", location: "Warsaw, Poland", about: "Film director 🎬", continent: "Europe", flag: "🇵🇱", avatar: { photo: null, bg: "#00C853", letter: "M" } },
  { id: "u37", name: "Nikos", handle: "@nikos_gr", location: "Athens, Greece", about: "Olive farmer & sailor ⛵", continent: "Europe", flag: "🇬🇷", avatar: { photo: null, bg: "#FF1744", letter: "N" } },
  { id: "u38", name: "Chloe", handle: "@chloe_nl", location: "Amsterdam, Netherlands", about: "Cyclist & artist 🚲", continent: "Europe", flag: "🇳🇱", avatar: { photo: null, bg: "#2979FF", letter: "C" } },
  { id: "u39", name: "Lena", handle: "@lena_ua", location: "Kyiv, Ukraine", about: "IT specialist 💻", continent: "Europe", flag: "🇺🇦", avatar: { photo: null, bg: "#FFD600", letter: "L" } },
  { id: "u40", name: "Viktor", handle: "@viktor_cz", location: "Prague, Czech Republic", about: "Brewer 🍺", continent: "Europe", flag: "🇨🇿", avatar: { photo: null, bg: "#00C853", letter: "V" } },
  { id: "u41", name: "Lars", handle: "@lars_no", location: "Oslo, Norway", about: "Marine biologist 🐋", continent: "Europe", flag: "🇳🇴", avatar: { photo: null, bg: "#FF1744", letter: "L" } },
  { id: "u42", name: "Ingrid", handle: "@ingrid_dk", location: "Copenhagen, Denmark", about: "UX designer 🖥️", continent: "Europe", flag: "🇩🇰", avatar: { photo: null, bg: "#2979FF", letter: "I" } },
  { id: "u43", name: "Katri", handle: "@katri_fi", location: "Helsinki, Finland", about: "Sauna enthusiast 🧖", continent: "Europe", flag: "🇫🇮", avatar: { photo: null, bg: "#FFD600", letter: "K" } },
  { id: "u44", name: "Ioana", handle: "@ioana_ro", location: "Bucharest, Romania", about: "Nurse 💉", continent: "Europe", flag: "🇷🇴", avatar: { photo: null, bg: "#00C853", letter: "I" } },
  { id: "u45", name: "Marko", handle: "@marko_rs", location: "Belgrade, Serbia", about: "Basketball coach 🏀", continent: "Europe", flag: "🇷🇸", avatar: { photo: null, bg: "#FF1744", letter: "M" } },
  { id: "u46", name: "Thea", handle: "@thea_ge", location: "Tbilisi, Georgia", about: "Wine maker 🍷", continent: "Europe", flag: "🇬🇪", avatar: { photo: null, bg: "#2979FF", letter: "T" } },
  { id: "u47", name: "Patrick", handle: "@patrick_ie", location: "Dublin, Ireland", about: "Pub quiz champion 🍺", continent: "Europe", flag: "🇮🇪", avatar: { photo: null, bg: "#FFD600", letter: "P" } },
  { id: "u48", name: "Marcel", handle: "@marcel_ch", location: "Zurich, Switzerland", about: "Banker ⌚", continent: "Europe", flag: "🇨🇭", avatar: { photo: null, bg: "#00C853", letter: "M" } },
  { id: "u49", name: "Jean", handle: "@jean_be", location: "Brussels, Belgium", about: "EU diplomat 🕊️", continent: "Europe", flag: "🇧🇪", avatar: { photo: null, bg: "#FF1744", letter: "J" } },
  { id: "u50", name: "Sophie", handle: "@sophie_at", location: "Vienna, Austria", about: "Opera singer 🎭", continent: "Europe", flag: "🇦🇹", avatar: { photo: null, bg: "#2979FF", letter: "S" } },
  { id: "u51", name: "Petra", handle: "@petra_hr", location: "Zagreb, Croatia", about: "Sea kayaker 🚣", continent: "Europe", flag: "🇭🇷", avatar: { photo: null, bg: "#FFD600", letter: "P" } },
  { id: "u3", name: "Carlos", handle: "@carlos_global", location: "Mexico City, Mexico", about: "Entrepreneur 🚀 Football fan", continent: "Americas", flag: "🇲🇽", avatar: { photo: null, bg: "#2979FF", letter: "C" } },
  { id: "u52", name: "James", handle: "@james_usa", location: "New York, USA", about: "Wall St. analyst 📈", continent: "Americas", flag: "🇺🇸", avatar: { photo: null, bg: "#FFD600", letter: "J" } },
  { id: "u53", name: "Emma", handle: "@emma_ca", location: "Toronto, Canada", about: "Hockey mom 🏒", continent: "Americas", flag: "🇨🇦", avatar: { photo: null, bg: "#00C853", letter: "E" } },
  { id: "u54", name: "Maria", handle: "@maria_cu", location: "Havana, Cuba", about: "Salsa dancer 💃", continent: "Americas", flag: "🇨🇺", avatar: { photo: null, bg: "#FF1744", letter: "M" } },
  { id: "u55", name: "Tyrone", handle: "@tyrone_jm", location: "Kingston, Jamaica", about: "Reggae musician 🎸", continent: "Americas", flag: "🇯🇲", avatar: { photo: null, bg: "#2979FF", letter: "T" } },
  { id: "u56", name: "Rosa", handle: "@rosa_gt", location: "Guatemala City, Guatemala", about: "Human rights lawyer ⚖️", continent: "Americas", flag: "🇬🇹", avatar: { photo: null, bg: "#FFD600", letter: "R" } },
  { id: "u57", name: "Lucia", handle: "@lucia_cr", location: "San José, Costa Rica", about: "Eco-tourism guide 🌴", continent: "Americas", flag: "🇨🇷", avatar: { photo: null, bg: "#00C853", letter: "L" } },
  { id: "u58", name: "Daniel", handle: "@daniel_pa", location: "Panama City, Panama", about: "Ship captain ⚓", continent: "Americas", flag: "🇵🇦", avatar: { photo: null, bg: "#FF1744", letter: "D" } },
  { id: "u59", name: "Sandra", handle: "@sandra_sv", location: "San Salvador, El Salvador", about: "Coffee grower ☕", continent: "Americas", flag: "🇸🇻", avatar: { photo: null, bg: "#2979FF", letter: "S" } },
  { id: "u60", name: "Lucas", handle: "@lucas_br", location: "São Paulo, Brazil", about: "Carnaval organizer 🎉", continent: "Americas", flag: "🇧🇷", avatar: { photo: null, bg: "#00C853", letter: "L" } },
  { id: "u61", name: "Valentina", handle: "@valentina_ar", location: "Buenos Aires, Argentina", about: "Tango dancer 🌹", continent: "Americas", flag: "🇦🇷", avatar: { photo: null, bg: "#FF1744", letter: "V" } },
  { id: "u62", name: "Camila", handle: "@camila_cl", location: "Santiago, Chile", about: "Winemaker 🍷", continent: "Americas", flag: "🇨🇱", avatar: { photo: null, bg: "#2979FF", letter: "C" } },
  { id: "u63", name: "Sebastian", handle: "@sebastian_co", location: "Bogotá, Colombia", about: "Coffee farmer ☕", continent: "Americas", flag: "🇨🇴", avatar: { photo: null, bg: "#FFD600", letter: "S" } },
  { id: "u64", name: "Isabel", handle: "@isabel_pe", location: "Lima, Peru", about: "Archaeologist 🏺", continent: "Americas", flag: "🇵🇪", avatar: { photo: null, bg: "#00C853", letter: "I" } },
  { id: "u65", name: "Mateo", handle: "@mateo_ve", location: "Caracas, Venezuela", about: "Chef 🍳", continent: "Americas", flag: "🇻🇪", avatar: { photo: null, bg: "#FF1744", letter: "M" } },
  { id: "u66", name: "Andrea", handle: "@andrea_ec", location: "Quito, Ecuador", about: "Mountain climber 🏔️", continent: "Americas", flag: "🇪🇨", avatar: { photo: null, bg: "#2979FF", letter: "A" } },
  { id: "u67", name: "Pablo", handle: "@pablo_bo", location: "La Paz, Bolivia", about: "Footballer ⚽", continent: "Americas", flag: "🇧🇴", avatar: { photo: null, bg: "#FFD600", letter: "P" } },
  { id: "u68", name: "Carmen", handle: "@carmen_uy", location: "Montevideo, Uruguay", about: "Writer 📖", continent: "Americas", flag: "🇺🇾", avatar: { photo: null, bg: "#00C853", letter: "C" } },
  { id: "u69", name: "Rafael", handle: "@rafael_py", location: "Asunción, Paraguay", about: "Farmer 🌾", continent: "Americas", flag: "🇵🇾", avatar: { photo: null, bg: "#FF1744", letter: "R" } },
  { id: "u70", name: "Trinidad", handle: "@trinidad_tt", location: "Port of Spain, Trinidad & Tobago", about: "Steelpan player 🥁", continent: "Americas", flag: "🇹🇹", avatar: { photo: null, bg: "#2979FF", letter: "T" } },
  { id: "u71", name: "Jean-Paul", handle: "@jean_ht", location: "Port-au-Prince, Haiti", about: "Visual artist 🎨", continent: "Americas", flag: "🇭🇹", avatar: { photo: null, bg: "#FFD600", letter: "J" } },
  { id: "u72", name: "Chioma", handle: "@chioma_ng", location: "Lagos, Nigeria", about: "Fashion designer 👗", continent: "Africa", flag: "🇳🇬", avatar: { photo: null, bg: "#2979FF", letter: "C" } },
  { id: "u73", name: "Siya", handle: "@siya_za", location: "Cape Town, South Africa", about: "Rugby player 🏉", continent: "Africa", flag: "🇿🇦", avatar: { photo: null, bg: "#FFD600", letter: "S" } },
  { id: "u74", name: "Amara", handle: "@amara_ke", location: "Nairobi, Kenya", about: "Safari guide 🦁", continent: "Africa", flag: "🇰🇪", avatar: { photo: null, bg: "#00C853", letter: "A" } },
  { id: "u75", name: "Hassan", handle: "@hassan_eg", location: "Cairo, Egypt", about: "Archaeologist 🏛️", continent: "Africa", flag: "🇪🇬", avatar: { photo: null, bg: "#FF1744", letter: "H" } },
  { id: "u76", name: "Abebe", handle: "@abebe_et", location: "Addis Ababa, Ethiopia", about: "Marathon runner 🏃", continent: "Africa", flag: "🇪🇹", avatar: { photo: null, bg: "#2979FF", letter: "A" } },
  { id: "u77", name: "Kwame", handle: "@kwame_gh", location: "Accra, Ghana", about: "Tech entrepreneur 💡", continent: "Africa", flag: "🇬🇭", avatar: { photo: null, bg: "#FFD600", letter: "K" } },
  { id: "u78", name: "Zara", handle: "@zara_ma", location: "Casablanca, Morocco", about: "Chef 🍲", continent: "Africa", flag: "🇲🇦", avatar: { photo: null, bg: "#00C853", letter: "Z" } },
  { id: "u79", name: "Aisha", handle: "@aisha_tz", location: "Dar es Salaam, Tanzania", about: "Marine biologist 🐠", continent: "Africa", flag: "🇹🇿", avatar: { photo: null, bg: "#FF1744", letter: "A" } },
  { id: "u80", name: "Moussa", handle: "@moussa_sn", location: "Dakar, Senegal", about: "Hip-hop artist 🎤", continent: "Africa", flag: "🇸🇳", avatar: { photo: null, bg: "#2979FF", letter: "M" } },
  { id: "u81", name: "Ndi", handle: "@ndi_cm", location: "Yaoundé, Cameroon", about: "Football player ⚽", continent: "Africa", flag: "🇨🇲", avatar: { photo: null, bg: "#FFD600", letter: "N" } },
  { id: "u82", name: "Fatou", handle: "@fatou_ci", location: "Abidjan, Ivory Coast", about: "Businesswoman 💼", continent: "Africa", flag: "🇨🇮", avatar: { photo: null, bg: "#00C853", letter: "F" } },
  { id: "u83", name: "Samuel", handle: "@samuel_ug", location: "Kampala, Uganda", about: "Wildlife photographer 📷", continent: "Africa", flag: "🇺🇬", avatar: { photo: null, bg: "#FF1744", letter: "S" } },
  { id: "u84", name: "Grace", handle: "@grace_zw", location: "Harare, Zimbabwe", about: "Teacher 📚", continent: "Africa", flag: "🇿🇼", avatar: { photo: null, bg: "#2979FF", letter: "G" } },
  { id: "u85", name: "Imani", handle: "@imani_rw", location: "Kigali, Rwanda", about: "Tech founder 🚀", continent: "Africa", flag: "🇷🇼", avatar: { photo: null, bg: "#FFD600", letter: "I" } },
  { id: "u86", name: "Sipho", handle: "@sipho_bw", location: "Gaborone, Botswana", about: "Diamond cutter 💎", continent: "Africa", flag: "🇧🇼", avatar: { photo: null, bg: "#00C853", letter: "S" } },
  { id: "u87", name: "Fatma", handle: "@fatma_tn", location: "Tunis, Tunisia", about: "Historian 📜", continent: "Africa", flag: "🇹🇳", avatar: { photo: null, bg: "#FF1744", letter: "F" } },
  { id: "u88", name: "Amira", handle: "@amira_dz", location: "Algiers, Algeria", about: "Doctor 🩺", continent: "Africa", flag: "🇩🇿", avatar: { photo: null, bg: "#2979FF", letter: "A" } },
  { id: "u89", name: "Adama", handle: "@adama_gn", location: "Conakry, Guinea", about: "Drummer 🥁", continent: "Africa", flag: "🇬🇳", avatar: { photo: null, bg: "#FFD600", letter: "A" } },
  { id: "u90", name: "Paul", handle: "@paul_mz", location: "Maputo, Mozambique", about: "Wildlife ranger 🦏", continent: "Africa", flag: "🇲🇿", avatar: { photo: null, bg: "#00C853", letter: "P" } },
  { id: "u91", name: "Lamin", handle: "@lamin_gm", location: "Banjul, Gambia", about: "Football coach ⚽", continent: "Africa", flag: "🇬🇲", avatar: { photo: null, bg: "#FF1744", letter: "L" } },
  { id: "u92", name: "Yaw", handle: "@yaw_bf", location: "Ouagadougou, Burkina Faso", about: "Farmer 🌽", continent: "Africa", flag: "🇧🇫", avatar: { photo: null, bg: "#2979FF", letter: "Y" } },
  { id: "u93", name: "Jack", handle: "@jack_au", location: "Sydney, Australia", about: "Surfer & barista ☕", continent: "Oceania", flag: "🇦🇺", avatar: { photo: null, bg: "#00C853", letter: "J" } },
  { id: "u94", name: "Aroha", handle: "@aroha_nz", location: "Auckland, New Zealand", about: "Maori culture keeper 🌿", continent: "Oceania", flag: "🇳🇿", avatar: { photo: null, bg: "#FF1744", letter: "A" } },
  { id: "u95", name: "Mere", handle: "@mere_fj", location: "Suva, Fiji", about: "Rugby star 🏉", continent: "Oceania", flag: "🇫🇯", avatar: { photo: null, bg: "#2979FF", letter: "M" } },
  { id: "u96", name: "Peter", handle: "@peter_pg", location: "Port Moresby, Papua New Guinea", about: "Tribal art creator 🎭", continent: "Oceania", flag: "🇵🇬", avatar: { photo: null, bg: "#FFD600", letter: "P" } },
  { id: "u97", name: "Sio", handle: "@sio_ws", location: "Apia, Samoa", about: "Fisherman 🎣", continent: "Oceania", flag: "🇼🇸", avatar: { photo: null, bg: "#00C853", letter: "S" } },
  { id: "u98", name: "Sione", handle: "@sione_to", location: "Nukualofa, Tonga", about: "Boxer 🥊", continent: "Oceania", flag: "🇹🇴", avatar: { photo: null, bg: "#FF1744", letter: "S" } },
  { id: "u99", name: "Mere", handle: "@mere_vu", location: "Port Vila, Vanuatu", about: "Island guide 🏝️", continent: "Oceania", flag: "🇻🇺", avatar: { photo: null, bg: "#2979FF", letter: "M" } },
  { id: "u100", name: "Mike", handle: "@mike_fm", location: "Palikir, Micronesia", about: "Deep sea diver 🤿", continent: "Oceania", flag: "🇫🇲", avatar: { photo: null, bg: "#FFD600", letter: "M" } },
  { id: "u101", name: "Tana", handle: "@tana_mg", location: "Antananarivo, Madagascar", about: "Lemur researcher 🐒", continent: "Africa", flag: "🇲🇬", avatar: { photo: null, bg: "#2979FF", letter: "T" } },
  { id: "u102", name: "Kofi", handle: "@kofi_tg", location: "Lomé, Togo", about: "Voodoo historian 📜", continent: "Africa", flag: "🇹🇬", avatar: { photo: null, bg: "#FFD600", letter: "K" } }
];


const SAMPLE_POSTS = [
  { id:1, userId:"u1", user:"Aryan", handle:"@aryan_world", avatar:{photo:null,bg:COLORS.yellow,letter:"A"}, content:"Hello world! 🌍 First post on Post app!", time:"2m ago", likes:12, comments:[], accent:COLORS.yellow, liked:false, likedColor:null, location:"Mumbai, India" },
  { id:2, userId:"u2", user:"Bella", handle:"@bella_creates", avatar:{photo:null,bg:COLORS.red,letter:"B"}, content:"Posting from London! This app is absolutely amazing! 🔥", time:"5m ago", likes:8, comments:[], accent:COLORS.red, liked:false, likedColor:null, location:"London, UK" },
  { id:3, userId:"u3", user:"Carlos", handle:"@carlos_global", avatar:{photo:null,bg:COLORS.blue,letter:"C"}, content:"Connected from Mexico 🇲🇽 — this is what social should feel like.", time:"10m ago", likes:24, comments:[], accent:COLORS.blue, liked:false, likedColor:null, location:"Mexico City, Mexico" },
  { id:4, userId:"u4", user:"Divya", handle:"@divya_india", avatar:{photo:null,bg:COLORS.green,letter:"D"}, content:"Hello world! 🙏 Posting from India. Post app rocks! 🚀", time:"15m ago", likes:31, comments:[], accent:COLORS.green, liked:false, likedColor:null, location:"Delhi, India" },
];

const LangCtx = createContext(T.en);

// ─── Country Codes ────────────────────────────────────────────────────────
const COUNTRY_CODES = [
  { code: "+1",   flag: "🇺🇸", name: "USA / Canada" },
  { code: "+7",   flag: "🇷🇺", name: "Russia" },
  { code: "+20",  flag: "🇪🇬", name: "Egypt" },
  { code: "+27",  flag: "🇿🇦", name: "South Africa" },
  { code: "+30",  flag: "🇬🇷", name: "Greece" },
  { code: "+31",  flag: "🇳🇱", name: "Netherlands" },
  { code: "+32",  flag: "🇧🇪", name: "Belgium" },
  { code: "+33",  flag: "🇫🇷", name: "France" },
  { code: "+34",  flag: "🇪🇸", name: "Spain" },
  { code: "+36",  flag: "🇭🇺", name: "Hungary" },
  { code: "+39",  flag: "🇮🇹", name: "Italy" },
  { code: "+40",  flag: "🇷🇴", name: "Romania" },
  { code: "+41",  flag: "🇨🇭", name: "Switzerland" },
  { code: "+43",  flag: "🇦🇹", name: "Austria" },
  { code: "+44",  flag: "🇬🇧", name: "United Kingdom" },
  { code: "+45",  flag: "🇩🇰", name: "Denmark" },
  { code: "+46",  flag: "🇸🇪", name: "Sweden" },
  { code: "+47",  flag: "🇳🇴", name: "Norway" },
  { code: "+48",  flag: "🇵🇱", name: "Poland" },
  { code: "+49",  flag: "🇩🇪", name: "Germany" },
  { code: "+51",  flag: "🇵🇪", name: "Peru" },
  { code: "+52",  flag: "🇲🇽", name: "Mexico" },
  { code: "+54",  flag: "🇦🇷", name: "Argentina" },
  { code: "+55",  flag: "🇧🇷", name: "Brazil" },
  { code: "+56",  flag: "🇨🇱", name: "Chile" },
  { code: "+57",  flag: "🇨🇴", name: "Colombia" },
  { code: "+58",  flag: "🇻🇪", name: "Venezuela" },
  { code: "+60",  flag: "🇲🇾", name: "Malaysia" },
  { code: "+61",  flag: "🇦🇺", name: "Australia" },
  { code: "+62",  flag: "🇮🇩", name: "Indonesia" },
  { code: "+63",  flag: "🇵🇭", name: "Philippines" },
  { code: "+64",  flag: "🇳🇿", name: "New Zealand" },
  { code: "+65",  flag: "🇸🇬", name: "Singapore" },
  { code: "+66",  flag: "🇹🇭", name: "Thailand" },
  { code: "+81",  flag: "🇯🇵", name: "Japan" },
  { code: "+82",  flag: "🇰🇷", name: "South Korea" },
  { code: "+84",  flag: "🇻🇳", name: "Vietnam" },
  { code: "+86",  flag: "🇨🇳", name: "China" },
  { code: "+90",  flag: "🇹🇷", name: "Turkey" },
  { code: "+91",  flag: "🇮🇳", name: "India" },
  { code: "+92",  flag: "🇵🇰", name: "Pakistan" },
  { code: "+94",  flag: "🇱🇰", name: "Sri Lanka" },
  { code: "+95",  flag: "🇲🇲", name: "Myanmar" },
  { code: "+98",  flag: "🇮🇷", name: "Iran" },
  { code: "+212", flag: "🇲🇦", name: "Morocco" },
  { code: "+213", flag: "🇩🇿", name: "Algeria" },
  { code: "+216", flag: "🇹🇳", name: "Tunisia" },
  { code: "+220", flag: "🇬🇲", name: "Gambia" },
  { code: "+221", flag: "🇸🇳", name: "Senegal" },
  { code: "+225", flag: "🇨🇮", name: "Ivory Coast" },
  { code: "+233", flag: "🇬🇭", name: "Ghana" },
  { code: "+234", flag: "🇳🇬", name: "Nigeria" },
  { code: "+237", flag: "🇨🇲", name: "Cameroon" },
  { code: "+250", flag: "🇷🇼", name: "Rwanda" },
  { code: "+251", flag: "🇪🇹", name: "Ethiopia" },
  { code: "+254", flag: "🇰🇪", name: "Kenya" },
  { code: "+255", flag: "🇹🇿", name: "Tanzania" },
  { code: "+256", flag: "🇺🇬", name: "Uganda" },
  { code: "+260", flag: "🇿🇲", name: "Zambia" },
  { code: "+263", flag: "🇿🇼", name: "Zimbabwe" },
  { code: "+267", flag: "🇧🇼", name: "Botswana" },
  { code: "+351", flag: "🇵🇹", name: "Portugal" },
  { code: "+353", flag: "🇮🇪", name: "Ireland" },
  { code: "+358", flag: "🇫🇮", name: "Finland" },
  { code: "+359", flag: "🇧🇬", name: "Bulgaria" },
  { code: "+370", flag: "🇱🇹", name: "Lithuania" },
  { code: "+371", flag: "🇱🇻", name: "Latvia" },
  { code: "+372", flag: "🇪🇪", name: "Estonia" },
  { code: "+380", flag: "🇺🇦", name: "Ukraine" },
  { code: "+381", flag: "🇷🇸", name: "Serbia" },
  { code: "+385", flag: "🇭🇷", name: "Croatia" },
  { code: "+420", flag: "🇨🇿", name: "Czech Republic" },
  { code: "+421", flag: "🇸🇰", name: "Slovakia" },
  { code: "+880", flag: "🇧🇩", name: "Bangladesh" },
  { code: "+886", flag: "🇹🇼", name: "Taiwan" },
  { code: "+962", flag: "🇯🇴", name: "Jordan" },
  { code: "+965", flag: "🇰🇼", name: "Kuwait" },
  { code: "+966", flag: "🇸🇦", name: "Saudi Arabia" },
  { code: "+968", flag: "🇴🇲", name: "Oman" },
  { code: "+971", flag: "🇦🇪", name: "UAE" },
  { code: "+972", flag: "🇮🇱", name: "Israel" },
  { code: "+974", flag: "🇶🇦", name: "Qatar" },
  { code: "+977", flag: "🇳🇵", name: "Nepal" },
  { code: "+994", flag: "🇦🇿", name: "Azerbaijan" },
  { code: "+995", flag: "🇬🇪", name: "Georgia" },
  { code: "+998", flag: "🇺🇿", name: "Uzbekistan" },
];

const AUTH_T = {
  subtitle:        "Verify to join 100+ countries on POST",
  withPhone:       "📱  Sign up with Phone Number",
  withEmail:       "📧  Sign up with Gmail / Email",
  continueWithout: "Continue without account →",
  enterPhone:      "Enter your phone number",
  enterEmail:      "Enter your email address",
  sendCode:        "SEND CODE →",
  sending:         "SENDING...",
  enterCode:       "Enter the 4-digit code",
  codeSentSMS:     "Code sent via SMS to",
  codeSentEmail:   "Code sent to",
  demoCode:        "Demo — your code:",
  verify:          "VERIFY & CONTINUE →",
  wrongCode:       "Incorrect code. Try again.",
  resend:          "Resend Code",
  back:            "← Back",
  smsNote:         "We'll send a 4-digit code via SMS",
  emailNote:       "We'll send a 4-digit code to your inbox",
  verifiedBadge:   "✓ Verified",
};

const useLang = () => useContext(LangCtx);

// ─── Icons ────────────────────────────────────────────────────────────────
const Ic = {
  Heart: ({ filled, color }) => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill={filled ? color : "none"} stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z" />
    </svg>
  ),
  Comment: ({ color }) => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    </svg>
  ),
  Send: ({ color }) => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" />
    </svg>
  ),
  Plus: () => (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#000" strokeWidth="2.8" strokeLinecap="round">
      <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  ),
  Home: ({ active }) => (
    <svg width="22" height="22" viewBox="0 0 24 24" fill={active ? COLORS.yellow : "none"} stroke={active ? COLORS.yellow : COLORS.muted} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><polyline points="9 22 9 12 15 12 15 22" />
    </svg>
  ),
  Search: ({ active }) => (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={active ? COLORS.green : COLORS.muted} strokeWidth="2" strokeLinecap="round">
      <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  ),
  People: ({ active }) => (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={active ? COLORS.red : COLORS.muted} strokeWidth="2" strokeLinecap="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  ),
  Profile: ({ active }) => (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={active ? COLORS.blue : COLORS.muted} strokeWidth="2" strokeLinecap="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
    </svg>
  ),
  Bell: ({ color, filled }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill={filled ? color : "none"} stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  ),
  Camera: ({ color = "#000" }) => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" />
      <circle cx="12" cy="13" r="4" />
    </svg>
  ),
  Pin: ({ color }) => (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z" /><circle cx="12" cy="10" r="3" />
    </svg>
  ),
  Edit: ({ color }) => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
      <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
    </svg>
  ),
  Check: ({ color }) => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  ),
  X: ({ color }) => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.8" strokeLinecap="round">
      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  ),
  Link: ({ color }) => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </svg>
  ),
  UserPlus: ({ color }) => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="8.5" cy="7" r="4" />
      <line x1="20" y1="8" x2="20" y2="14" /><line x1="23" y1="11" x2="17" y2="11" />
    </svg>
  ),
  Globe: ({ color }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  ),
  Chat: ({ active }) => (
    <svg width="22" height="22" viewBox="0 0 24 24" fill={active ? COLORS.blue : "none"} stroke={active ? COLORS.blue : COLORS.muted} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    </svg>
  ),
};

// ─── Messages Tab ─────────────────────────────────────────────────────────
const EMOJIS = ["😀","😂","😍","😎","👍","❤️","🔥","🎉","🙏","😢"];

function MessagesTab() {
  const [messages, setMessages] = useState([
    { id: 1, sender: "Krishna", text: "Welcome to Post Messenger 👋", time: "10:30 AM", status: "Read" }
  ]);
  const [text, setText] = useState("");
  const [search, setSearch] = useState("");
  const [showEmoji, setShowEmoji] = useState(false);
  const [typing, setTyping] = useState(false);

  const filtered = messages.filter(m => m.text.toLowerCase().includes(search.toLowerCase()));

  function sendMessage() {
    if (!text.trim()) return;
    setMessages(prev => [...prev, {
      id: Date.now(), sender: "You", text,
      time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      status: "Sent"
    }]);
    setText(""); setTyping(false);
  }

  return (
    <div style={{ background: COLORS.card, border: `2px solid ${COLORS.blue}`, boxShadow: `4px 4px 0 ${COLORS.blue}`, overflow: "hidden" }}>
      <div style={{ height: 4, display: "flex" }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>

      <div style={{ padding: "12px 14px", borderBottom: "1px solid #1e1e1e", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontWeight: 900, fontSize: 15, color: COLORS.blue, letterSpacing: 1 }}>💬 MESSAGES</div>
        <input
          value={search} onChange={e => setSearch(e.target.value)}
          placeholder="🔍 Search..."
          style={{ padding: "6px 10px", background: "#0a0a0a", border: `1.5px solid ${COLORS.blue}`, color: "#fff", fontSize: 12, outline: "none", width: 130 }}
        />
      </div>

      <div style={{ height: 380, overflowY: "auto", padding: "12px 14px", display: "flex", flexDirection: "column", gap: 10 }}>
        {filtered.map(msg => (
          <div key={msg.id} style={{
            maxWidth: "75%", padding: "10px 12px", fontSize: 13, lineHeight: 1.5,
            alignSelf: msg.sender === "You" ? "flex-end" : "flex-start",
            background: msg.sender === "You" ? COLORS.blue : "#1e1e1e",
            color: "#fff", border: `2px solid ${msg.sender === "You" ? COLORS.blue : "#333"}`,
            boxShadow: `3px 3px 0 ${msg.sender === "You" ? "#1a55cc" : "#2a2a2a"}`
          }}>
            {msg.sender !== "You" && <div style={{ fontSize: 10, color: COLORS.muted, fontWeight: 700, marginBottom: 4 }}>{msg.sender}</div>}
            <div>{msg.text}</div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 6 }}>
              <span style={{ fontSize: 10, color: msg.sender === "You" ? "rgba(255,255,255,0.6)" : COLORS.muted }}>{msg.time}</span>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <span style={{ fontSize: 10, color: msg.sender === "You" ? "rgba(255,255,255,0.7)" : COLORS.muted }}>{msg.status === "Read" ? "✓✓" : "✓"}</span>
                <button style={{ fontSize: 10, color: COLORS.green, background: "transparent", border: `1px solid ${COLORS.green}`, padding: "1px 5px", cursor: "pointer" }}>🌐</button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {typing && (
        <div style={{ padding: "4px 14px", fontSize: 11, color: COLORS.muted }}>✍️ Typing...</div>
      )}

      {showEmoji && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, padding: "10px 14px", borderTop: "1px solid #1e1e1e", background: "#0d0d0d" }}>
          {EMOJIS.map(emoji => (
            <button key={emoji} onClick={() => setText(t => t + emoji)}
              style={{ fontSize: 22, background: "transparent", border: "none", cursor: "pointer" }}>
              {emoji}
            </button>
          ))}
        </div>
      )}

      <div style={{ display: "flex", gap: 8, padding: "12px 14px", borderTop: "1px solid #1e1e1e", alignItems: "center" }}>
        <button onClick={() => setShowEmoji(s => !s)}
          style={{ fontSize: 20, background: "transparent", border: "none", cursor: "pointer" }}>😊</button>
        <input
          value={text}
          onChange={e => { setText(e.target.value); setTyping(e.target.value.length > 0); }}
          onKeyDown={e => e.key === "Enter" && sendMessage()}
          placeholder="Type a message..."
          style={{ flex: 1, padding: "9px 12px", background: "#0a0a0a", border: `1.5px solid ${COLORS.blue}`, color: "#fff", fontSize: 13, outline: "none" }}
        />
        <button onClick={sendMessage}
          style={{ padding: "9px 16px", background: COLORS.blue, border: "none", color: "#fff", fontWeight: 900, fontSize: 13, cursor: "pointer" }}>
          SEND
        </button>
      </div>
    </div>
  );
}

// ─── Avatar ───────────────────────────────────────────────────────────────
function Avatar({ avatar, size = 40, border, borderColor }) {
  return (
    <div style={{
      width: size, height: size, borderRadius: 0, flexShrink: 0,
      border: border ? `${border}px solid ${borderColor || "#fff"}` : "none",
      overflow: "hidden", display: "flex", alignItems: "center", justifyContent: "center",
      background: avatar?.photo ? "transparent" : (avatar?.bg || COLORS.yellow),
      fontWeight: 900, fontSize: size * 0.44, color: "#000",
    }}>
      {avatar?.photo
        ? <img src={avatar.photo} alt="" style={{ width: "100%", height: "100%", objectFit: "cover" }} />
        : (avatar?.letter || "?")}
    </div>
  );
}

// ─── PostCard ─────────────────────────────────────────────────────────────
function PostCard({ post, onLike, onComment }) {
  const t = useLang();
  const [open, setOpen] = useState(false);
  const [showReactions, setShowReactions] = useState(false);
  const [txt, setTxt] = useState("");
  const submit = () => { if (!txt.trim()) return; onComment(post.id, txt.trim()); setTxt(""); };
  const REACTION_OPTS = [COLORS.yellow, COLORS.green, COLORS.red, COLORS.blue];
  const handleReaction = (color) => { onLike(post.id, color); setShowReactions(false); };
  return (
    <div style={{ background: COLORS.card, border: `2px solid ${post.accent}`, marginBottom: 14, overflow: "hidden", boxShadow: `4px 4px 0 ${post.accent}` }}>
      <div style={{ height: 4, background: post.accent }} />
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "11px 13px 7px" }}>
        <Avatar avatar={post.avatar} size={40} border={2} borderColor={post.accent} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 700, fontSize: 13, color: "#fff" }}>{post.user}</div>
          <div style={{ fontSize: 11, color: COLORS.muted }}>{post.handle} · {post.time}</div>
          {post.location && (
            <div style={{ display: "flex", alignItems: "center", gap: 3, marginTop: 1 }}>
              <Ic.Pin color={post.accent} />
              <span style={{ fontSize: 10, color: post.accent, fontWeight: 600 }}>{post.location}</span>
            </div>
          )}
        </div>
        <div style={{ background: post.accent, color: "#000", fontSize: 8, fontWeight: 800, padding: "2px 6px", letterSpacing: 1 }}>{t.post}</div>
      </div>
      <div style={{ padding: "2px 13px 11px", fontSize: 14, color: "#fff", lineHeight: 1.6 }}>{post.content}</div>
      <div style={{ display: "flex", borderTop: "1px solid #1e1e1e" }}>
        <button onClick={() => setShowReactions(p => !p)} style={{
          flex: 1, padding: "9px 0", background: post.liked ? `${post.likedColor}22` : "transparent",
          border: "none", cursor: "pointer", display: "flex", alignItems: "center",
          justifyContent: "center", gap: 5, color: post.liked ? post.likedColor : COLORS.muted,
          fontSize: 12, fontWeight: 700, borderRight: "1px solid #1e1e1e",
        }}>
          <Ic.Heart filled={post.liked} color={post.liked ? post.likedColor : COLORS.muted} />{post.likes}
        </button>
        <button onClick={() => setOpen(!open)} style={{
          flex: 1, padding: "9px 0", background: open ? "#1a1a1a" : "transparent",
          border: "none", cursor: "pointer", display: "flex", alignItems: "center",
          justifyContent: "center", gap: 5, color: open ? post.accent : COLORS.muted, fontSize: 12, fontWeight: 700,
        }}>
          <Ic.Comment color={open ? post.accent : COLORS.muted} />{post.comments.length}
        </button>
      </div>
      {showReactions && (
        <div style={{ display: "flex", borderTop: "1px solid #1e1e1e", background: "#0d0d0d" }}>
          {REACTION_OPTS.map(color => {
            const isActive = post.liked && post.likedColor === color;
            return (
              <button key={color} onClick={() => handleReaction(color)} style={{
                flex: 1, padding: "10px 0", background: isActive ? `${color}22` : "transparent",
                border: "none", borderRight: "1px solid #1e1e1e", cursor: "pointer",
                display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 4,
              }}>
                <Ic.Heart filled={isActive} color={color} />
                <div style={{ width: 16, height: 3, background: color, opacity: isActive ? 1 : 0.45 }} />
              </button>
            );
          })}
        </div>
      )}
      {open && (
        <div style={{ padding: "9px 13px", borderTop: "1px solid #1e1e1e", background: "#0d0d0d" }}>
          {post.comments.length === 0 && <div style={{ color: COLORS.muted, fontSize: 12, marginBottom: 7 }}>{t.firstComment}</div>}
          {post.comments.map((c, i) => (
            <div key={i} style={{ fontSize: 12, color: "#ccc", marginBottom: 5, paddingLeft: 8, borderLeft: `2px solid ${post.accent}` }}>{c}</div>
          ))}
          <div style={{ display: "flex", gap: 7, marginTop: 7 }}>
            <input value={txt} onChange={e => setTxt(e.target.value)} onKeyDown={e => e.key === "Enter" && submit()}
              placeholder={t.writeComment} style={{ flex: 1, padding: "7px 9px", background: "#1a1a1a", border: `1.5px solid ${post.accent}`, color: "#fff", fontSize: 12, outline: "none" }} />
            <button onClick={submit} style={{ background: post.accent, border: "none", width: 32, height: 32, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Ic.Send color="#000" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Compose Modal ────────────────────────────────────────────────────────
function ComposeModal({ user, onClose, onPost }) {
  const t = useLang();
  const [txt, setTxt] = useState("");
  const [accent, setAccent] = useState(COLORS.yellow);
  const [withLoc, setWithLoc] = useState(!!user.location);
  const submit = () => { if (!txt.trim()) return; onPost(txt.trim(), accent, withLoc ? user.location : ""); onClose(); };
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 200, background: "rgba(0,0,0,0.9)", display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }}>
      <div style={{ background: "#111", border: `2px solid ${accent}`, boxShadow: `6px 6px 0 ${accent}`, width: "100%", maxWidth: 430, overflow: "hidden" }}>
        <div style={{ height: 4, background: accent }} />
        <div style={{ padding: 18 }}>
          <div style={{ fontWeight: 900, fontSize: 16, color: accent, marginBottom: 12, letterSpacing: 1 }}>{t.newPost}</div>
          <div style={{ display: "flex", gap: 7, marginBottom: 12, alignItems: "center" }}>
            {ACCENTS.map(c => <button key={c} onClick={() => setAccent(c)} style={{ width: 24, height: 24, background: c, border: accent === c ? "3px solid #fff" : "2px solid transparent", cursor: "pointer" }} />)}
            <span style={{ color: COLORS.muted, fontSize: 11, marginLeft: 3 }}>{t.color}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 10 }}>
            <Avatar avatar={user.avatar} size={34} border={2} borderColor={accent} />
            <div>
              <div style={{ fontWeight: 700, fontSize: 12, color: "#fff" }}>{user.name}</div>
              {user.location && (
                <label style={{ display: "flex", alignItems: "center", gap: 4, cursor: "pointer" }}>
                  <input type="checkbox" checked={withLoc} onChange={e => setWithLoc(e.target.checked)} style={{ accentColor: accent }} />
                  <span style={{ fontSize: 11, color: COLORS.muted }}>📍 {user.location}</span>
                </label>
              )}
            </div>
          </div>
          <textarea value={txt} onChange={e => setTxt(e.target.value)} placeholder={t.whatsOnMind} autoFocus maxLength={280}
            style={{ width: "100%", minHeight: 100, background: "#0a0a0a", border: "1.5px solid #2a2a2a", color: "#fff", fontSize: 14, padding: "9px 11px", resize: "none", outline: "none", fontFamily: "inherit", lineHeight: 1.6, boxSizing: "border-box" }} />
          <div style={{ fontSize: 10, color: COLORS.muted, textAlign: "right", marginTop: 3 }}>{txt.length}/280</div>
          <div style={{ display: "flex", gap: 9, marginTop: 12 }}>
            <button onClick={onClose} style={{ flex: 1, padding: "9px 0", background: "transparent", border: "2px solid #2a2a2a", color: COLORS.muted, fontWeight: 700, fontSize: 13, cursor: "pointer" }}>{t.cancel}</button>
            <button onClick={submit} disabled={!txt.trim()} style={{ flex: 2, padding: "9px 0", background: txt.trim() ? accent : "#222", border: "none", color: txt.trim() ? "#000" : "#444", fontWeight: 900, fontSize: 13, cursor: txt.trim() ? "pointer" : "default" }}>{t.postNow}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Edit Profile Modal ───────────────────────────────────────────────────
function EditProfileModal({ user, onClose, onSave }) {
  const t = useLang();
  const [name, setName] = useState(user.name);
  const [handle, setHandle] = useState(user.handle);
  const [location, setLocation] = useState(user.location || "");
  const [about, setAbout] = useState(user.about || "");
  const [bg, setBg] = useState(user.avatar.bg || COLORS.yellow);
  const [photo, setPhoto] = useState(user.avatar.photo || null);
  const fileRef = useRef();
  const onFile = e => { const f = e.target.files[0]; if (!f) return; const r = new FileReader(); r.onload = ev => setPhoto(ev.target.result); r.readAsDataURL(f); };
  const save = () => {
    if (!name.trim()) return;
    const h = handle.trim() ? (handle.startsWith("@") ? handle : `@${handle}`) : `@${name.toLowerCase().replace(/\s+/g, "_")}`;
    onSave({ ...user, name: name.trim(), handle: h, location: location.trim(), about: about.trim(), avatar: { ...user.avatar, photo, bg, letter: name[0]?.toUpperCase() || "?" } });
    onClose();
  };
  const prev = { photo, bg, letter: name[0]?.toUpperCase() || "?" };
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 200, background: "rgba(0,0,0,0.92)", display: "flex", alignItems: "center", justifyContent: "center", padding: 16, overflowY: "auto" }}>
      <div style={{ background: "#111", border: `2px solid ${COLORS.blue}`, boxShadow: `6px 6px 0 ${COLORS.blue}`, width: "100%", maxWidth: 400, overflow: "hidden", margin: "auto" }}>
        <div style={{ height: 4, display: "flex" }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>
        <div style={{ padding: 18 }}>
          <div style={{ fontWeight: 900, fontSize: 15, color: COLORS.blue, marginBottom: 16 }}>{t.profileEdit}</div>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 16 }}>
            <div style={{ position: "relative", flexShrink: 0 }}>
              <Avatar avatar={prev} size={66} border={3} borderColor={COLORS.blue} />
              <button onClick={() => fileRef.current.click()} style={{ position: "absolute", bottom: -5, right: -5, width: 24, height: 24, background: COLORS.yellow, border: "2px solid #000", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Ic.Camera color="#000" />
              </button>
              <input ref={fileRef} type="file" accept="image/*" onChange={onFile} style={{ display: "none" }} />
            </div>
            <div>
              <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 6 }}>{t.avatarColor}</div>
              <div style={{ display: "flex", gap: 7 }}>{ACCENTS.map(c => <button key={c} onClick={() => setBg(c)} style={{ width: 26, height: 26, background: c, border: bg === c ? "3px solid #fff" : "2px solid transparent", cursor: "pointer" }} />)}</div>
              {photo && <button onClick={() => setPhoto(null)} style={{ marginTop: 7, fontSize: 10, color: COLORS.red, background: "transparent", border: `1px solid ${COLORS.red}`, cursor: "pointer", padding: "2px 7px" }}>{t.removePhoto}</button>}
            </div>
          </div>
          {[[t.nameStar, name, setName, t.yourName, 40], [t.handle, handle, setHandle, t.username, 30], [t.location, location, setLocation, t.cityCountry, 60]].map(([label, val, set, ph, mx]) => (
            <div key={label} style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 3, fontWeight: 600 }}>{label}</div>
              <input value={val} onChange={e => set(e.target.value)} placeholder={ph} maxLength={mx} style={{ width: "100%", padding: "8px 11px", background: "#0a0a0a", border: "1.5px solid #2a2a2a", color: "#fff", fontSize: 13, outline: "none", boxSizing: "border-box" }} />
            </div>
          ))}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 3, fontWeight: 600 }}>{t.about}</div>
            <textarea value={about} onChange={e => setAbout(e.target.value)} placeholder={t.aboutPlaceholder} maxLength={150}
              style={{ width: "100%", minHeight: 60, background: "#0a0a0a", border: "1.5px solid #2a2a2a", color: "#fff", fontSize: 13, padding: "8px 11px", resize: "none", outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} />
            <div style={{ fontSize: 10, color: COLORS.muted, textAlign: "right" }}>{about.length}/150</div>
          </div>
          <div style={{ display: "flex", gap: 9 }}>
            <button onClick={onClose} style={{ flex: 1, padding: "9px 0", background: "transparent", border: "2px solid #2a2a2a", color: COLORS.muted, fontWeight: 700, fontSize: 13, cursor: "pointer" }}>{t.cancel}</button>
            <button onClick={save} style={{ flex: 2, padding: "9px 0", background: COLORS.blue, border: "none", color: "#fff", fontWeight: 900, fontSize: 13, cursor: "pointer" }}>{t.save}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Profile Setup ────────────────────────────────────────────────────────
function ProfileSetup({ onDone, authInfo }) {
  const t = useLang();
  const [name, setName] = useState("");
  const [handle, setHandle] = useState("");
  const [location, setLocation] = useState("");
  const [about, setAbout] = useState("");
  const [bg, setBg] = useState(COLORS.yellow);
  const [photo, setPhoto] = useState(null);
  const fileRef = useRef();
  const onFile = e => { const f = e.target.files[0]; if (!f) return; const r = new FileReader(); r.onload = ev => setPhoto(ev.target.result); r.readAsDataURL(f); };
  const submit = () => {
    if (!name.trim()) return;
    const h = handle.trim() ? (handle.startsWith("@") ? handle : `@${handle}`) : `@${name.toLowerCase().replace(/\s+/g, "_")}`;
    onDone({ name: name.trim(), handle: h, location: location.trim(), about: about.trim(), avatar: { photo, bg, letter: name[0].toUpperCase() } });
  };
  const prev = { photo, bg, letter: name[0]?.toUpperCase() || "?" };
  return (
    <div style={{ minHeight: "100vh", background: COLORS.dark, display: "flex", alignItems: "center", justifyContent: "center", padding: 16, overflowY: "auto" }}>
      <div style={{ width: "100%", maxWidth: 370, background: "#111", border: `2px solid ${COLORS.yellow}`, boxShadow: `6px 6px 0 ${COLORS.yellow}`, overflow: "hidden" }}>
        <div style={{ display: "flex", height: 6 }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>
        <div style={{ padding: 22 }}>
          <div style={{ textAlign: "center", marginBottom: 20 }}>
            <div style={{ display: "inline-flex", width: 52, height: 52, background: COLORS.yellow, alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 26, color: "#000", border: "3px solid #fff" }}>P</div>
            <div style={{ fontWeight: 900, fontSize: 22, color: "#fff", letterSpacing: 3, marginTop: 7 }}>POST</div>
            <div style={{ fontSize: 12, color: COLORS.muted, marginTop: 3 }}>{t.tagline}</div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 13, marginBottom: 16 }}>
            <div style={{ position: "relative", flexShrink: 0 }}>
              <Avatar avatar={prev} size={64} border={3} borderColor={COLORS.yellow} />
              <button onClick={() => fileRef.current.click()} style={{ position: "absolute", bottom: -5, right: -5, width: 24, height: 24, background: COLORS.yellow, border: "2px solid #000", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Ic.Camera color="#000" />
              </button>
              <input ref={fileRef} type="file" accept="image/*" onChange={onFile} style={{ display: "none" }} />
            </div>
            <div>
              <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 6 }}>{t.choosePhotoColor}</div>
              <div style={{ display: "flex", gap: 7 }}>{ACCENTS.map(c => <button key={c} onClick={() => setBg(c)} style={{ width: 26, height: 26, background: c, border: bg === c ? "3px solid #fff" : "2px solid transparent", cursor: "pointer" }} />)}</div>
            </div>
          </div>
          {[[t.nameStar, name, setName, t.yourName, 40], [t.handle, handle, setHandle, t.usernameOpt, 30], [t.location, location, setLocation, t.cityCountry, 60]].map(([label, val, set, ph, mx]) => (
            <div key={label} style={{ marginBottom: 9 }}>
              <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 3, fontWeight: 600 }}>{label}</div>
              <input value={val} onChange={e => set(e.target.value)} placeholder={ph} maxLength={mx} style={{ width: "100%", padding: "8px 11px", background: "#0a0a0a", border: "1.5px solid #2a2a2a", color: "#fff", fontSize: 13, outline: "none", boxSizing: "border-box" }} />
            </div>
          ))}
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 3, fontWeight: 600 }}>{t.about}</div>
            <textarea value={about} onChange={e => setAbout(e.target.value)} placeholder={t.aboutPlaceholder} maxLength={150}
              style={{ width: "100%", minHeight: 55, background: "#0a0a0a", border: "1.5px solid #2a2a2a", color: "#fff", fontSize: 13, padding: "8px 11px", resize: "none", outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} />
          </div>
          {authInfo && (
            <div style={{ background: `${COLORS.green}22`, border: `1.5px solid ${COLORS.green}`, padding: "9px 12px", marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: COLORS.green, fontSize: 14 }}>✓</span>
              <div>
                <div style={{ fontSize: 10, color: COLORS.green, fontWeight: 700 }}>{AUTH_T.verifiedBadge} · {authInfo.type === "phone" ? "📱 Phone" : "📧 Email"}</div>
                <div style={{ fontSize: 12, color: "#fff", fontWeight: 600 }}>{authInfo.contact}</div>
              </div>
            </div>
          )}
          <button onClick={submit} disabled={!name.trim()} style={{ width: "100%", padding: "12px 0", background: name.trim() ? COLORS.yellow : "#222", color: name.trim() ? "#000" : "#444", fontWeight: 900, fontSize: 14, letterSpacing: 1, border: "none", cursor: name.trim() ? "pointer" : "default" }}>
            {t.joinWorld}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Toast ────────────────────────────────────────────────────────────────
function Toast({ msg, color, onClose }) {
  return (
    <div style={{ position: "fixed", top: 62, left: "50%", transform: "translateX(-50%)", zIndex: 999, background: "#111", border: `2px solid ${color}`, boxShadow: `3px 3px 0 ${color}`, padding: "9px 16px", display: "flex", alignItems: "center", gap: 8, minWidth: 220, maxWidth: 340 }}>
      <div style={{ width: 8, height: 8, background: color, flexShrink: 0 }} />
      <span style={{ fontSize: 13, color: "#fff", fontWeight: 600, flex: 1 }}>{msg}</span>
      <button onClick={onClose} style={{ background: "transparent", border: "none", color: COLORS.muted, cursor: "pointer", fontSize: 14, padding: 0 }}>✕</button>
    </div>
  );
}

// ─── Language Picker ──────────────────────────────────────────────────────
function LangPicker({ current, onSelect, onClose }) {
  const t = useLang();
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 300, background: "rgba(0,0,0,0.92)", display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }}>
      <div style={{ background: "#111", border: `2px solid ${COLORS.green}`, boxShadow: `6px 6px 0 ${COLORS.green}`, width: "100%", maxWidth: 420, overflow: "hidden" }}>
        <div style={{ height: 4, display: "flex" }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>
        <div style={{ padding: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <div style={{ fontWeight: 900, fontSize: 15, color: COLORS.green }}>🌐 {t.langPicker}</div>
            <button onClick={onClose} style={{ background: "transparent", border: "none", color: COLORS.muted, cursor: "pointer", fontSize: 18 }}>✕</button>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
            {Object.entries(LANGS).map(([code, lang]) => (
              <button key={code} onClick={() => { onSelect(code); onClose(); }} style={{
                padding: "10px 8px", background: current === code ? `${COLORS.green}22` : "#0a0a0a",
                border: `2px solid ${current === code ? COLORS.green : "#2a2a2a"}`,
                cursor: "pointer", display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
                boxShadow: current === code ? `2px 2px 0 ${COLORS.green}` : "none",
              }}>
                <span style={{ fontSize: 20 }}>{lang.flag}</span>
                <span style={{ fontSize: 10, color: current === code ? COLORS.green : "#ccc", fontWeight: current === code ? 800 : 500, textAlign: "center" }}>{lang.name}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── User Card (Discover/Friends) ─────────────────────────────────────────
function UserCard({ u, isFriend, sent, onConnect, onCancelRequest }) {
  const t = useLang();
  return (
    <div style={{ background: COLORS.card, border: `2px solid #1e1e1e`, marginBottom: 10, overflow: "hidden", boxShadow: `3px 3px 0 #1e1e1e` }}>
      <div style={{ height: 3, background: u.avatar.bg }} />
      <div style={{ padding: "11px 13px", display: "flex", alignItems: "center", gap: 11 }}>
        <div style={{ position: "relative", flexShrink: 0 }}>
          <Avatar avatar={u.avatar} size={44} border={2} borderColor={u.avatar.bg} />
          <span style={{ position: "absolute", bottom: -4, right: -4, fontSize: 12 }}>{u.flag}</span>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 700, fontSize: 13, color: "#fff" }}>{u.name}</div>
          <div style={{ fontSize: 11, color: COLORS.muted }}>{u.handle}</div>
          {u.location && (
            <div style={{ display: "flex", alignItems: "center", gap: 3, marginTop: 2 }}>
              <Ic.Pin color={u.avatar.bg} />
              <span style={{ fontSize: 10, color: u.avatar.bg, fontWeight: 600 }}>{u.location}</span>
            </div>
          )}
          {u.about && <div style={{ fontSize: 11, color: "#aaa", marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{u.about}</div>}
        </div>
        <div>
          {isFriend ? (
            <div style={{ background: COLORS.green + "22", border: `1.5px solid ${COLORS.green}`, color: COLORS.green, fontSize: 10, fontWeight: 800, padding: "5px 10px" }}>{t.friend}</div>
          ) : sent ? (
            <button onClick={() => onCancelRequest(u.id)} style={{ background: "#222", border: `1.5px solid #444`, color: COLORS.muted, fontSize: 10, fontWeight: 800, padding: "5px 10px", cursor: "pointer" }}>{t.pending}</button>
          ) : (
            <button onClick={() => onConnect(u)} style={{ background: COLORS.yellow, border: "none", color: "#000", fontSize: 10, fontWeight: 900, padding: "6px 11px", cursor: "pointer", display: "flex", alignItems: "center", gap: 4 }}>
              <Ic.UserPlus color="#000" /> {t.connect}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Friends Tab ──────────────────────────────────────────────────────────
function FriendsTab({ user, friends, requests, sentRequests, onAccept, onDecline, onConnect, onCancelRequest, showToast }) {
  const t = useLang();
  const [view, setView] = useState("people");
  const [continent, setContinent] = useState("all");
  const [inviteLink] = useState(`https://postapp.world/invite/${user.handle.replace("@", "")}`);
  const [copied, setCopied] = useState(false);
  const pendingCount = requests.length;

  const copyLink = () => {
    navigator.clipboard?.writeText(inviteLink).catch(() => {});
    setCopied(true);
    showToast(t.linkCopiedToast, COLORS.green);
    setTimeout(() => setCopied(false), 2000);
  };

  const CONTINENTS = [
    { key: "all", label: t.all },
    { key: "Asia", label: t.asia },
    { key: "Europe", label: t.europe },
    { key: "Americas", label: t.americas },
    { key: "Africa", label: t.africa },
    { key: "Oceania", label: t.oceania },
  ];

  const filteredUsers = WORLD_USERS.filter(u =>
    u.id !== "me" && (continent === "all" || u.continent === continent)
  );

  const tabs = [
    { id: "people", label: t.discover },
    { id: "friends", label: `${t.friends} (${friends.length})` },
    { id: "requests", label: `${t.requests}${pendingCount > 0 ? ` (${pendingCount})` : ""}` },
    { id: "invite", label: t.invite },
  ];

  return (
    <div>
      <div style={{ display: "flex", marginBottom: 14, background: "#111", border: "2px solid #1e1e1e" }}>
        {tabs.map(tab => (
          <button key={tab.id} onClick={() => setView(tab.id)} style={{
            flex: 1, padding: "9px 4px", background: view === tab.id ? COLORS.red : "transparent",
            border: "none", cursor: "pointer", color: view === tab.id ? "#000" : COLORS.muted,
            fontSize: 10, fontWeight: 800, letterSpacing: 0.3, borderRight: "1px solid #1e1e1e",
          }}>{tab.label}</button>
        ))}
      </div>

      {view === "people" && (
        <div>
          <div style={{ display: "flex", gap: 5, marginBottom: 12, overflowX: "auto", paddingBottom: 4 }}>
            {CONTINENTS.map(c => (
              <button key={c.key} onClick={() => setContinent(c.key)} style={{
                flexShrink: 0, padding: "5px 10px", background: continent === c.key ? COLORS.yellow : "#111",
                border: `1.5px solid ${continent === c.key ? COLORS.yellow : "#333"}`,
                color: continent === c.key ? "#000" : COLORS.muted,
                fontSize: 10, fontWeight: 800, cursor: "pointer", whiteSpace: "nowrap",
              }}>{c.label}</button>
            ))}
          </div>
          <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 10, fontWeight: 700, letterSpacing: 1 }}>
            {t.discoverPeople} — {filteredUsers.length} {t.friends.toLowerCase()}
          </div>
          {filteredUsers.map(u => (
            <UserCard key={u.id} u={u}
              isFriend={friends.includes(u.id)}
              sent={sentRequests.includes(u.id)}
              onConnect={onConnect} onCancelRequest={onCancelRequest} />
          ))}
        </div>
      )}

      {view === "friends" && (
        <div>
          <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 10, fontWeight: 700, letterSpacing: 1 }}>{t.yourFriends}</div>
          {friends.length === 0 ? (
            <div style={{ background: "#111", border: "2px dashed #2a2a2a", padding: 30, textAlign: "center" }}>
              <div style={{ fontSize: 28, marginBottom: 8 }}>🌐</div>
              <div style={{ color: COLORS.muted, fontSize: 13 }}>{t.noFriendsYet}</div>
              <div style={{ color: COLORS.muted, fontSize: 12, marginTop: 4 }}>{t.goToDiscover}</div>
            </div>
          ) : (
            WORLD_USERS.filter(u => friends.includes(u.id)).map(u => (
              <div key={u.id} style={{ background: COLORS.card, border: `2px solid ${COLORS.green}`, marginBottom: 10, overflow: "hidden", boxShadow: `3px 3px 0 ${COLORS.green}` }}>
                <div style={{ height: 3, background: COLORS.green }} />
                <div style={{ padding: "11px 13px", display: "flex", alignItems: "center", gap: 11 }}>
                  <div style={{ position: "relative", flexShrink: 0 }}>
                    <Avatar avatar={u.avatar} size={44} border={2} borderColor={COLORS.green} />
                    <span style={{ position: "absolute", bottom: -4, right: -4, fontSize: 12 }}>{u.flag}</span>
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 700, fontSize: 13, color: "#fff" }}>{u.name}</div>
                    <div style={{ fontSize: 11, color: COLORS.muted }}>{u.handle}</div>
                    {u.location && <div style={{ fontSize: 10, color: COLORS.green, fontWeight: 600, marginTop: 2 }}>{u.location}</div>}
                  </div>
                  <div style={{ background: COLORS.green + "22", border: `1.5px solid ${COLORS.green}`, color: COLORS.green, fontSize: 10, fontWeight: 800, padding: "5px 9px" }}>{t.friend}</div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {view === "requests" && (
        <div>
          <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 10, fontWeight: 700, letterSpacing: 1 }}>{t.connRequests}</div>
          {requests.length === 0 ? (
            <div style={{ background: "#111", border: "2px dashed #2a2a2a", padding: 30, textAlign: "center" }}>
              <div style={{ fontSize: 28, marginBottom: 8 }}>📭</div>
              <div style={{ color: COLORS.muted, fontSize: 13 }}>{t.noPendingReq}</div>
            </div>
          ) : (
            requests.map(req => (
              <div key={req.userId} style={{ background: COLORS.card, border: `2px solid ${COLORS.yellow}`, marginBottom: 10, overflow: "hidden", boxShadow: `3px 3px 0 ${COLORS.yellow}` }}>
                <div style={{ height: 3, background: COLORS.yellow }} />
                <div style={{ padding: "11px 13px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 11, marginBottom: 10 }}>
                    <Avatar avatar={req.avatar} size={44} border={2} borderColor={COLORS.yellow} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 700, fontSize: 13, color: "#fff" }}>{req.name}</div>
                      <div style={{ fontSize: 11, color: COLORS.muted }}>{req.handle}</div>
                      {req.location && <div style={{ fontSize: 10, color: COLORS.yellow, fontWeight: 600, marginTop: 2 }}>{req.location}</div>}
                    </div>
                  </div>
                  <div style={{ fontSize: 12, color: "#aaa", marginBottom: 10, padding: "7px 9px", background: "#0d0d0d", borderLeft: `3px solid ${COLORS.yellow}` }}>
                    "{req.message || `${req.name} ${t.wantsToConnect}`}"
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button onClick={() => onAccept(req.userId)} style={{ flex: 1, padding: "8px 0", background: COLORS.green, border: "none", color: "#000", fontWeight: 900, fontSize: 12, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 5 }}>
                      <Ic.Check color="#000" /> {t.accept}
                    </button>
                    <button onClick={() => onDecline(req.userId)} style={{ flex: 1, padding: "8px 0", background: "transparent", border: `2px solid ${COLORS.red}`, color: COLORS.red, fontWeight: 900, fontSize: 12, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 5 }}>
                      <Ic.X color={COLORS.red} /> {t.decline}
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {view === "invite" && (
        <div>
          <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 12, fontWeight: 700, letterSpacing: 1 }}>{t.inviteFriends}</div>
          <div style={{ background: "#111", border: `2px solid ${COLORS.yellow}`, boxShadow: `4px 4px 0 ${COLORS.yellow}`, marginBottom: 14, overflow: "hidden" }}>
            <div style={{ height: 4, display: "flex" }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>
            <div style={{ padding: 16 }}>
              <div style={{ fontSize: 22, textAlign: "center", marginBottom: 8 }}>🌍</div>
              <div style={{ fontWeight: 900, fontSize: 15, color: "#fff", textAlign: "center", marginBottom: 4 }}>{t.inviteYourFriends}</div>
              <div style={{ fontSize: 12, color: COLORS.muted, textAlign: "center", marginBottom: 14 }}>{t.shareInviteLink}</div>
              <div style={{ background: "#0a0a0a", border: `1.5px solid ${COLORS.yellow}`, padding: "9px 12px", display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <Ic.Link color={COLORS.yellow} />
                <span style={{ fontSize: 11, color: "#ccc", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inviteLink}</span>
              </div>
              <button onClick={copyLink} style={{ width: "100%", padding: "11px 0", background: copied ? COLORS.green : COLORS.yellow, border: "none", color: "#000", fontWeight: 900, fontSize: 13, cursor: "pointer", letterSpacing: 1 }}>
                {copied ? t.linkCopied : t.copyLink}
              </button>
            </div>
          </div>
          <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 10, fontWeight: 700, letterSpacing: 1 }}>{t.shareVia}</div>
          {[
            { label: t.shareWA, emoji: "💬", color: "#25D366", msg: `Hey! Join me on POST app! ${inviteLink}` },
            { label: t.shareTwitter, emoji: "🐦", color: "#1DA1F2", msg: `Join me on POST app! ${inviteLink}` },
            { label: t.shareSMS, emoji: "📱", color: COLORS.blue, msg: `Join me on POST: ${inviteLink}` },
          ].map(({ label, emoji, color, msg }) => (
            <button key={label} onClick={() => showToast(`${emoji} ${msg.slice(0, 50)}...`, color)}
              style={{ width: "100%", padding: "11px 14px", background: "#111", border: `2px solid ${color}`, color: "#fff", display: "flex", alignItems: "center", gap: 10, cursor: "pointer", marginBottom: 8, textAlign: "left", boxShadow: `3px 3px 0 ${color}` }}>
              <span style={{ fontSize: 18 }}>{emoji}</span>
              <span style={{ fontSize: 13, fontWeight: 700 }}>{label}</span>
            </button>
          ))}
          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 8, fontWeight: 700, letterSpacing: 1 }}>{t.inviteByName}</div>
            <DirectInvite showToast={showToast} />
          </div>
        </div>
      )}
    </div>
  );
}

function DirectInvite({ showToast }) {
  const t = useLang();
  const [name, setName] = useState("");
  const send = () => {
    if (!name.trim()) return;
    showToast(`✉️ ${t.inviteSent} ${name}!`, COLORS.green);
    setName("");
  };
  return (
    <div style={{ background: "#111", border: `2px solid #2a2a2a`, padding: 13 }}>
      <div style={{ fontSize: 12, color: COLORS.muted, marginBottom: 8 }}>{t.enterFriendName}</div>
      <div style={{ display: "flex", gap: 8 }}>
        <input value={name} onChange={e => setName(e.target.value)} onKeyDown={e => e.key === "Enter" && send()}
          placeholder={t.friendName} style={{ flex: 1, padding: "8px 11px", background: "#0a0a0a", border: `1.5px solid ${COLORS.yellow}`, color: "#fff", fontSize: 13, outline: "none" }} />
        <button onClick={send} disabled={!name.trim()} style={{ padding: "8px 14px", background: name.trim() ? COLORS.yellow : "#222", border: "none", color: name.trim() ? "#000" : "#444", fontWeight: 900, fontSize: 12, cursor: name.trim() ? "pointer" : "default" }}>{t.send}</button>
      </div>
    </div>
  );
}

// ─── OTP Input Boxes ──────────────────────────────────────────────────────
function OTPBoxes({ onComplete, accent, resetKey }) {
  const [digits, setDigits] = useState(["", "", "", ""]);
  const r0 = useRef(), r1 = useRef(), r2 = useRef(), r3 = useRef();
  const refs = [r0, r1, r2, r3];

  useEffect(() => { setDigits(["", "", "", ""]); refs[0].current?.focus(); }, [resetKey]);

  const handleChange = (i, val) => {
    const v = val.replace(/\D/g, "").slice(-1);
    const d = [...digits]; d[i] = v; setDigits(d);
    if (v && i < 3) refs[i + 1].current?.focus();
    if (d.filter(x => x !== "").length === 4) onComplete(d.join(""));
  };
  const handleKey = (i, e) => {
    if (e.key === "Backspace" && !digits[i] && i > 0) refs[i - 1].current?.focus();
  };
  return (
    <div style={{ display: "flex", gap: 10, justifyContent: "center", margin: "20px 0" }}>
      {digits.map((d, i) => (
        <input key={`${resetKey}-${i}`} ref={refs[i]} value={d} maxLength={2} inputMode="numeric"
          onChange={e => handleChange(i, e.target.value)} onKeyDown={e => handleKey(i, e)}
          style={{ width: 58, height: 68, textAlign: "center", fontSize: 30, fontWeight: 900,
            background: "#0a0a0a", border: `2.5px solid ${d ? accent : "#2a2a2a"}`,
            color: "#fff", outline: "none", boxSizing: "border-box",
            boxShadow: d ? `3px 3px 0 ${accent}` : "none" }} />
      ))}
    </div>
  );
}

// ─── Country Code Picker ──────────────────────────────────────────────────
function CountryPicker({ selected, onSelect, onClose }) {
  const [q, setQ] = useState("");
  const filtered = COUNTRY_CODES.filter(c =>
    c.name.toLowerCase().includes(q.toLowerCase()) || c.code.includes(q)
  );
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 500, background: "rgba(0,0,0,0.95)", display: "flex", alignItems: "flex-end" }}>
      <div style={{ width: "100%", background: "#111", border: `2px solid ${COLORS.yellow}`, maxHeight: "72vh", display: "flex", flexDirection: "column" }}>
        <div style={{ height: 4, display: "flex" }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>
        <div style={{ padding: "12px 14px", display: "flex", alignItems: "center", gap: 10 }}>
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search country or +code..."
            autoFocus style={{ flex: 1, padding: "9px 11px", background: "#0a0a0a", border: `1.5px solid ${COLORS.yellow}`, color: "#fff", fontSize: 13, outline: "none" }} />
          <button onClick={onClose} style={{ background: "transparent", border: "none", color: COLORS.muted, fontSize: 22, cursor: "pointer", padding: 0 }}>✕</button>
        </div>
        <div style={{ overflowY: "auto", flex: 1 }}>
          {filtered.map(c => (
            <button key={c.code + c.name} onClick={() => { onSelect(c); onClose(); }}
              style={{ width: "100%", padding: "12px 14px", background: selected.code === c.code ? `${COLORS.yellow}22` : "transparent",
                border: "none", borderBottom: "1px solid #1e1e1e", cursor: "pointer",
                display: "flex", alignItems: "center", gap: 12, textAlign: "left" }}>
              <span style={{ fontSize: 20 }}>{c.flag}</span>
              <span style={{ flex: 1, fontSize: 13, color: "#fff", fontWeight: 500 }}>{c.name}</span>
              <span style={{ fontSize: 14, color: COLORS.yellow, fontWeight: 800 }}>{c.code}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── OTP Screen ───────────────────────────────────────────────────────────
function OTPScreen({ contact, accent, onBack, onVerify, demoCode }) {
  const [error, setError]     = useState("");
  const [loading, setLoading] = useState(false);
  const [resetKey, setResetKey] = useState(0);
  const isSMS = contact.startsWith("+");

  const verify = async (entered) => {
    setLoading(true); setError("");
    try {
      await onVerify(entered);
    } catch (err) {
      setError(err.message || AUTH_T.wrongCode);
      setResetKey(k => k + 1);
    } finally {
      setLoading(false);
    }
  };

  const resend = () => { setError(""); setResetKey(k => k + 1); };

  return (
    <div style={{ padding: 22 }}>
      <button onClick={onBack} style={{ background: "transparent", border: "none", color: accent, fontSize: 13, fontWeight: 700, cursor: "pointer", marginBottom: 18 }}>{AUTH_T.back}</button>
      <div style={{ fontWeight: 900, fontSize: 17, color: "#fff", marginBottom: 6 }}>{AUTH_T.enterCode}</div>
      <div style={{ fontSize: 12, color: COLORS.muted }}>{isSMS ? AUTH_T.codeSentSMS : AUTH_T.codeSentEmail}</div>
      <div style={{ fontSize: 13, color: accent, fontWeight: 700, marginBottom: 16, marginTop: 3, wordBreak: "break-all" }}>{contact}</div>

      {/* Demo mode only: show code in UI */}
      {demoCode && (
        <div style={{ background: `${COLORS.green}22`, border: `1.5px solid ${COLORS.green}`, padding: "11px 14px", marginBottom: 8, display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 18 }}>📋</span>
          <div>
            <div style={{ fontSize: 9, color: COLORS.green, fontWeight: 700, letterSpacing: 1 }}>DEMO — YOUR CODE</div>
            <div style={{ fontSize: 32, fontWeight: 900, color: "#fff", letterSpacing: 12, marginTop: 2 }}>{demoCode}</div>
          </div>
        </div>
      )}

      {!demoCode && (
        <div style={{ background: "#0d0d0d", border: "1px solid #2a2a2a", padding: "10px 14px", marginBottom: 8, fontSize: 12, color: COLORS.muted }}>
          📬 {isSMS ? "Check your SMS messages" : "Check your inbox (and spam folder)"}
        </div>
      )}

      <OTPBoxes onComplete={verify} accent={accent} resetKey={resetKey} />

      {loading && <div style={{ textAlign: "center", color: accent, fontSize: 12, fontWeight: 700, marginBottom: 10 }}>Verifying...</div>}
      {error  && <div style={{ color: COLORS.red, fontSize: 12, textAlign: "center", marginBottom: 10, fontWeight: 700 }}>{error}</div>}

      <button onClick={resend} style={{ width: "100%", padding: "9px 0", background: "transparent", border: "1.5px solid #333", color: COLORS.muted, fontWeight: 700, fontSize: 12, cursor: "pointer" }}>
        {AUTH_T.resend}
      </button>
    </div>
  );
}

// ─── Phone Auth ───────────────────────────────────────────────────────────
function PhoneAuth({ onBack, onVerified }) {
  const [country, setCountry]     = useState({ code: "+91", flag: "🇮🇳", name: "India" });
  const [phone, setPhone]         = useState("");
  const [step, setStep]           = useState("input");
  const [sending, setSending]     = useState(false);
  const [error, setError]         = useState("");
  const [showPicker, setShowPicker] = useState(false);
  const [confirmResult, setConfirmResult] = useState(null);
  const [demoCode, setDemoCode]   = useState("");
  const recaptchaRef = useRef(null);
  const full = `${country.code}${phone}`;

  const sendCode = async () => {
    if (phone.trim().length < 5) return;
    setSending(true); setError("");

    if (DEMO_MODE) {
      // ── DEMO: simulate SMS ────────────────────────────────────────────
      const code = Math.floor(1000 + Math.random() * 9000).toString();
      setDemoCode(code);
      setTimeout(() => { setSending(false); setStep("otp"); }, 1000);
      return;
    }

    // ── REAL: Firebase Phone Auth ─────────────────────────────────────
    try {
      if (recaptchaRef.current) { try { recaptchaRef.current.clear(); } catch (_) {} }
      // Uncomment after npm install firebase:
      // const verifier = new RecaptchaVerifier("recaptcha-phone", { size: "invisible" }, firebaseAuth);
      // recaptchaRef.current = verifier;
      // const result = await signInWithPhoneNumber(firebaseAuth, full, verifier);
      // setConfirmResult(result);
      setStep("otp");
    } catch (err) {
      setError(err.message || "Failed to send SMS. Check phone number & Firebase config.");
    } finally {
      setSending(false);
    }
  };

  const verifyOTP = async (entered) => {
    if (DEMO_MODE) {
      if (entered === demoCode) { onVerified({ type: "phone", contact: full }); }
      else { throw new Error(AUTH_T.wrongCode); }
      return;
    }
    // Real Firebase verify:
    // await confirmResult.confirm(entered);  // throws if wrong
    // onVerified({ type: "phone", contact: full });
  };

  if (step === "otp") return (
    <OTPScreen contact={full} accent={COLORS.yellow}
      demoCode={DEMO_MODE ? demoCode : null}
      onBack={() => { setStep("input"); setDemoCode(""); }}
      onVerify={verifyOTP} />
  );

  return (
    <div style={{ padding: 22 }}>
      <button onClick={onBack} style={{ background: "transparent", border: "none", color: COLORS.yellow, fontSize: 13, fontWeight: 700, cursor: "pointer", marginBottom: 18 }}>{AUTH_T.back}</button>
      <div style={{ fontWeight: 900, fontSize: 17, color: "#fff", marginBottom: 4 }}>{AUTH_T.enterPhone}</div>
      <div style={{ fontSize: 12, color: COLORS.muted, marginBottom: 18 }}>{AUTH_T.smsNote}</div>

      <div style={{ display: "flex", gap: 8, marginBottom: 18 }}>
        <button onClick={() => setShowPicker(true)} style={{ padding: "11px 12px", background: "#0a0a0a", border: `1.5px solid ${COLORS.yellow}`, color: "#fff", cursor: "pointer", display: "flex", alignItems: "center", gap: 6, fontWeight: 800, fontSize: 13, flexShrink: 0, boxShadow: `2px 2px 0 ${COLORS.yellow}` }}>
          <span style={{ fontSize: 16 }}>{country.flag}</span>
          <span>{country.code}</span>
          <span style={{ color: COLORS.muted, fontSize: 10 }}>▼</span>
        </button>
        <input value={phone} onChange={e => setPhone(e.target.value.replace(/\D/g, ""))}
          placeholder="Phone number" inputMode="numeric" maxLength={15} autoFocus
          style={{ flex: 1, padding: "11px 13px", background: "#0a0a0a",
            border: `1.5px solid ${phone.length >= 5 ? COLORS.yellow : "#2a2a2a"}`,
            color: "#fff", fontSize: 15, outline: "none" }} />
      </div>

      {error && <div style={{ color: COLORS.red, fontSize: 12, marginBottom: 10, fontWeight: 600 }}>{error}</div>}

      <button onClick={sendCode} disabled={phone.trim().length < 5 || sending} style={{
        width: "100%", padding: "14px 0",
        background: phone.trim().length >= 5 ? COLORS.yellow : "#222", border: "none",
        color: phone.trim().length >= 5 ? "#000" : "#444",
        fontWeight: 900, fontSize: 14, cursor: phone.trim().length >= 5 ? "pointer" : "default", letterSpacing: 1 }}>
        {sending ? "Sending SMS..." : AUTH_T.sendCode}
      </button>

      {/* Firebase invisible reCAPTCHA anchor */}
      <div id="recaptcha-phone" />

      {showPicker && <CountryPicker selected={country} onSelect={setCountry} onClose={() => setShowPicker(false)} />}
    </div>
  );
}

// ─── Email Auth ───────────────────────────────────────────────────────────
function EmailAuth({ onBack, onVerified }) {
  const [email, setEmail]     = useState("");
  const [step, setStep]       = useState("input");
  const [sending, setSending] = useState(false);
  const [error, setError]     = useState("");
  const [demoCode, setDemoCode] = useState("");
  const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  const sendCode = async () => {
    if (!valid) return;
    setSending(true); setError("");
    const code = Math.floor(1000 + Math.random() * 9000).toString();

    if (DEMO_MODE) {
      // ── DEMO: skip real email ─────────────────────────────────────────
      setDemoCode(code);
      setTimeout(() => { setSending(false); setStep("otp"); }, 1000);
      return;
    }

    // ── REAL: send via EmailJS ────────────────────────────────────────
    setDemoCode(code); // store for verification
    try {
      // Uncomment after npm install @emailjs/browser and setup:
      // await emailjs.send(
      //   EMAILJS_CONFIG.serviceId,
      //   EMAILJS_CONFIG.templateId,
      //   { to_email: email, otp_code: code, app_name: "POST App" },
      //   EMAILJS_CONFIG.publicKey
      // );
      setStep("otp");
    } catch (err) {
      setError("Email send failed. Check your EmailJS config.");
      setDemoCode("");
    } finally {
      setSending(false);
    }
  };

  const verifyOTP = async (entered) => {
    if (entered === demoCode) { onVerified({ type: "email", contact: email }); }
    else { throw new Error(AUTH_T.wrongCode); }
  };

  if (step === "otp") return (
    <OTPScreen contact={email} accent={COLORS.blue}
      demoCode={DEMO_MODE ? demoCode : null}
      onBack={() => { setStep("input"); setDemoCode(""); }}
      onVerify={verifyOTP} />
  );

  return (
    <div style={{ padding: 22 }}>
      <button onClick={onBack} style={{ background: "transparent", border: "none", color: COLORS.blue, fontSize: 13, fontWeight: 700, cursor: "pointer", marginBottom: 18 }}>{AUTH_T.back}</button>
      <div style={{ fontWeight: 900, fontSize: 17, color: "#fff", marginBottom: 4 }}>{AUTH_T.enterEmail}</div>
      <div style={{ fontSize: 12, color: COLORS.muted, marginBottom: 18 }}>{AUTH_T.emailNote}</div>

      <input value={email} onChange={e => setEmail(e.target.value)} placeholder="your@gmail.com"
        type="email" inputMode="email" autoCapitalize="none" autoFocus
        style={{ width: "100%", padding: "12px 13px", background: "#0a0a0a",
          border: `1.5px solid ${valid ? COLORS.blue : "#2a2a2a"}`, color: "#fff",
          fontSize: 14, outline: "none", marginBottom: 18, boxSizing: "border-box",
          boxShadow: valid ? `2px 2px 0 ${COLORS.blue}` : "none" }} />

      {error && <div style={{ color: COLORS.red, fontSize: 12, marginBottom: 10, fontWeight: 600 }}>{error}</div>}

      <button onClick={sendCode} disabled={!valid || sending} style={{
        width: "100%", padding: "14px 0",
        background: valid ? COLORS.blue : "#222", border: "none",
        color: valid ? "#fff" : "#444",
        fontWeight: 900, fontSize: 14, cursor: valid ? "pointer" : "default", letterSpacing: 1 }}>
        {sending ? "Sending Email..." : AUTH_T.sendCode}
      </button>
    </div>
  );
}

// ─── Auth Screen ──────────────────────────────────────────────────────────
function AuthScreen({ onVerified, onSkip }) {
  const [method, setMethod] = useState(null);

  const shell = (accent, child) => (
    <div style={{ minHeight: "100vh", background: COLORS.dark, display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }}>
      <div style={{ width: "100%", maxWidth: 400, background: "#111", border: `2px solid ${accent}`, boxShadow: `6px 6px 0 ${accent}`, overflow: "hidden" }}>
        <div style={{ height: 4, display: "flex" }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>
        {child}
      </div>
    </div>
  );

  if (method === "phone") return shell(COLORS.yellow, <PhoneAuth onBack={() => setMethod(null)} onVerified={onVerified} />);
  if (method === "email") return shell(COLORS.blue,   <EmailAuth onBack={() => setMethod(null)} onVerified={onVerified} />);

  return (
    <div style={{ minHeight: "100vh", background: COLORS.dark, display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }}>
      <div style={{ width: "100%", maxWidth: 370, background: "#111", border: `2px solid ${COLORS.yellow}`, boxShadow: `6px 6px 0 ${COLORS.yellow}`, overflow: "hidden" }}>
        <div style={{ height: 6, display: "flex" }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>
        <div style={{ padding: 24 }}>
          <div style={{ textAlign: "center", marginBottom: 28 }}>
            <div style={{ display: "inline-flex", width: 66, height: 66, background: COLORS.yellow, alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 34, color: "#000", border: "3px solid #fff", marginBottom: 10 }}>P</div>
            <div style={{ fontWeight: 900, fontSize: 26, color: "#fff", letterSpacing: 4 }}>POST</div>
            <div style={{ fontSize: 12, color: COLORS.muted, marginTop: 7 }}>{AUTH_T.subtitle}</div>
            {DEMO_MODE && (
              <div style={{ marginTop: 10, padding: "5px 12px", background: `${COLORS.yellow}22`, border: `1px solid ${COLORS.yellow}`, display: "inline-block", fontSize: 10, color: COLORS.yellow, fontWeight: 700 }}>
                DEMO MODE — Add Firebase & EmailJS to go live
              </div>
            )}
          </div>

          <button onClick={() => setMethod("phone")} style={{ width: "100%", padding: "16px", background: "#0a0a0a", border: `2px solid ${COLORS.yellow}`, cursor: "pointer", display: "flex", alignItems: "center", gap: 14, marginBottom: 12, boxShadow: `3px 3px 0 ${COLORS.yellow}`, textAlign: "left" }}>
            <span style={{ fontSize: 30 }}>📱</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 900, fontSize: 15, color: "#fff" }}>Phone Number</div>
              <div style={{ fontSize: 11, color: COLORS.muted, marginTop: 3 }}>4-digit code via SMS{DEMO_MODE ? " (demo)" : " · Firebase"}</div>
            </div>
            <span style={{ color: COLORS.yellow, fontSize: 20, fontWeight: 900 }}>→</span>
          </button>

          <button onClick={() => setMethod("email")} style={{ width: "100%", padding: "16px", background: "#0a0a0a", border: `2px solid ${COLORS.blue}`, cursor: "pointer", display: "flex", alignItems: "center", gap: 14, marginBottom: 24, boxShadow: `3px 3px 0 ${COLORS.blue}`, textAlign: "left" }}>
            <span style={{ fontSize: 30 }}>📧</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 900, fontSize: 15, color: "#fff" }}>Gmail / Email</div>
              <div style={{ fontSize: 11, color: COLORS.muted, marginTop: 3 }}>4-digit code via email{DEMO_MODE ? " (demo)" : " · EmailJS"}</div>
            </div>
            <span style={{ color: COLORS.blue, fontSize: 20, fontWeight: 900 }}>→</span>
          </button>

          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
            <div style={{ flex: 1, height: 1, background: "#2a2a2a" }} />
            <span style={{ fontSize: 11, color: COLORS.muted }}>or</span>
            <div style={{ flex: 1, height: 1, background: "#2a2a2a" }} />
          </div>

          <button onClick={onSkip} style={{ width: "100%", padding: "11px 0", background: "transparent", border: "1.5px solid #2a2a2a", color: COLORS.muted, fontWeight: 700, fontSize: 13, cursor: "pointer" }}>
            {AUTH_T.continueWithout}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────
export default function PostApp() {
  const [lang, setLang] = useState(() => {
    const bl = navigator.language?.slice(0, 2);
    return T[bl] ? bl : "en";
  });
  const t = T[lang] || T.en;
  const dir = LANGS[lang]?.dir || "ltr";

  const [user, setUser] = useState(null);
  const [posts, setPosts] = useState(SAMPLE_POSTS);
  const [tab, setTab] = useState("home");
  const [showCompose, setShowCompose] = useState(false);
  const [showEditProfile, setShowEditProfile] = useState(false);
  const [showLangPicker, setShowLangPicker] = useState(false);
  const [search, setSearch] = useState("");
  const [toast, setToast] = useState(null);
  const [friends, setFriends] = useState([]);
  const [sentRequests, setSentRequests] = useState([]);
  const [requests, setRequests] = useState([
    { userId: "u5", name: "Emre", handle: "@emre_ist", location: "Istanbul, Turkey", avatar: { photo: null, bg: COLORS.yellow, letter: "E" }, message: "Hey! I want to connect with you on POST 🎧" },
  ]);
  const [notifCount, setNotifCount] = useState(1);
  const [authDone, setAuthDone] = useState(false);
  const [authInfo, setAuthInfo] = useState(null);

  const showToast = (msg, color = COLORS.yellow) => { setToast({ msg, color }); setTimeout(() => setToast(null), 3000); };
  const handleConnect = (targetUser) => { setSentRequests(p => [...p, targetUser.id]); showToast(`📨 ${t.connectReqSent} ${targetUser.name}!`, COLORS.blue); };
  const handleCancelRequest = (userId) => { setSentRequests(p => p.filter(id => id !== userId)); showToast(t.reqCancelled, COLORS.muted); };
  const handleAccept = (userId) => {
    setFriends(p => [...p, userId]);
    setRequests(p => p.filter(r => r.userId !== userId));
    setNotifCount(c => Math.max(0, c - 1));
    const u = WORLD_USERS.find(u => u.id === userId);
    showToast(`🎉 ${u?.name} ${t.isNowFriend}`, COLORS.green);
  };
  const handleDecline = (userId) => { setRequests(p => p.filter(r => r.userId !== userId)); setNotifCount(c => Math.max(0, c - 1)); showToast(t.reqDeclined, COLORS.red); };
  const handlePost = (text, accent, location) => {
    setPosts(p => [{ id: ++postIdCtr, userId: "me", user: user.name, handle: user.handle, avatar: { ...user.avatar }, content: text, time: t.justNow, likes: 0, comments: [], accent, liked: false, likedColor: null, location: location || "" }, ...p]);
    setTab("home");
  };
  const handleLike = (id, color) => setPosts(p => p.map(post => {
    if (post.id !== id) return post;
    if (post.liked && post.likedColor === color) return { ...post, liked: false, likedColor: null, likes: post.likes - 1 };
    else if (post.liked) return { ...post, likedColor: color };
    else return { ...post, liked: true, likedColor: color, likes: post.likes + 1 };
  }));
  const handleComment = (id, text) => setPosts(p => p.map(post => post.id === id ? { ...post, comments: [...post.comments, text] } : post));
  const handleSaveProfile = updated => { setUser(updated); setPosts(p => p.map(post => post.userId === "me" ? { ...post, user: updated.name, handle: updated.handle, avatar: { ...updated.avatar } } : post)); };

  const myPosts = posts.filter(p => p.userId === "me");
  const explorePosts = search ? posts.filter(p =>
    p.content.toLowerCase().includes(search.toLowerCase()) ||
    p.user.toLowerCase().includes(search.toLowerCase()) ||
    (p.location || "").toLowerCase().includes(search.toLowerCase())
  ) : posts;

  const navItems = [
    { id: "home", icon: <Ic.Home active={tab === "home"} />, label: t.home, color: COLORS.yellow },
    { id: "explore", icon: <Ic.Search active={tab === "explore"} />, label: t.explore, color: COLORS.green },
    { id: "messages", icon: <Ic.Chat active={tab === "messages"} />, label: "Chat", color: COLORS.blue },
    { id: "friends", icon: <Ic.People active={tab === "friends"} />, label: t.friends, color: COLORS.red, badge: notifCount },
    { id: "profile", icon: <Ic.Profile active={tab === "profile"} />, label: t.profile, color: COLORS.blue },
  ];

  const langBtn = (
    <div style={{ position: "fixed", top: 12, right: 16, zIndex: 100 }}>
      <button onClick={() => setShowLangPicker(true)} style={{ background: "#111", border: `2px solid ${COLORS.green}`, cursor: "pointer", padding: "6px 8px", display: "flex", alignItems: "center", gap: 5 }}>
        <Ic.Globe color={COLORS.green} />
        <span style={{ fontSize: 10, color: COLORS.green, fontWeight: 700 }}>{LANGS[lang]?.flag} {lang.toUpperCase()}</span>
      </button>
    </div>
  );

  if (!user) {
    if (!authDone) return (
      <LangCtx.Provider value={t}>
        <div dir={dir}>
          {langBtn}
          {showLangPicker && <LangPicker current={lang} onSelect={setLang} onClose={() => setShowLangPicker(false)} />}
          <AuthScreen
            onVerified={info => { setAuthInfo(info); setAuthDone(true); }}
            onSkip={() => setAuthDone(true)}
          />
        </div>
      </LangCtx.Provider>
    );
    return (
      <LangCtx.Provider value={t}>
        <div dir={dir}>
          {langBtn}
          {showLangPicker && <LangPicker current={lang} onSelect={setLang} onClose={() => setShowLangPicker(false)} />}
          <ProfileSetup onDone={setUser} authInfo={authInfo} />
        </div>
      </LangCtx.Provider>
    );
  }

  return (
    <LangCtx.Provider value={t}>
      <div dir={dir} style={{ background: COLORS.dark, minHeight: "100vh", fontFamily: "'Segoe UI', sans-serif", color: "#fff" }}>
        {toast && <Toast msg={toast.msg} color={toast.color} onClose={() => setToast(null)} />}

        <div style={{ position: "sticky", top: 0, zIndex: 50, background: "#0a0a0a", borderBottom: "2px solid #1a1a1a", display: "flex", alignItems: "center", padding: "0 14px", height: 52 }}>
          <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 3, display: "flex" }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>
          <div style={{ fontWeight: 900, fontSize: 21, letterSpacing: 3 }}>
            <span style={{ color: COLORS.yellow }}>P</span><span style={{ color: COLORS.red }}>O</span><span style={{ color: COLORS.blue }}>S</span><span style={{ color: COLORS.green }}>T</span>
          </div>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
            <button onClick={() => setShowLangPicker(true)} style={{ background: "transparent", border: `1px solid #333`, cursor: "pointer", padding: "4px 7px", display: "flex", alignItems: "center", gap: 4 }}>
              <span style={{ fontSize: 13 }}>{LANGS[lang]?.flag}</span>
              <Ic.Globe color={COLORS.muted} />
            </button>
            {notifCount > 0 && (
              <button onClick={() => setTab("friends")} style={{ position: "relative", background: "transparent", border: "none", cursor: "pointer", padding: 4 }}>
                <Ic.Bell color={COLORS.yellow} filled />
                <div style={{ position: "absolute", top: 0, right: 0, width: 14, height: 14, background: COLORS.red, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 8, fontWeight: 900, color: "#fff", border: "1px solid #000" }}>{notifCount}</div>
              </button>
            )}
            <button onClick={() => setTab("profile")} style={{ background: "transparent", border: "none", cursor: "pointer", padding: 0 }}>
              <Avatar avatar={user.avatar} size={30} border={2} borderColor={COLORS.yellow} />
            </button>
          </div>
        </div>

        <div style={{ maxWidth: 500, margin: "0 auto", padding: "14px 11px 76px" }}>
          {tab === "home" && posts.map(p => <PostCard key={p.id} post={p} onLike={handleLike} onComment={handleComment} />)}

          {tab === "explore" && (
            <>
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder={t.searchPlaceholder}
                style={{ width: "100%", padding: "11px 13px", background: "#111", border: `2px solid ${COLORS.green}`, color: "#fff", fontSize: 13, outline: "none", marginBottom: 14, boxSizing: "border-box", boxShadow: `3px 3px 0 ${COLORS.green}` }} />
              {explorePosts.length === 0
                ? <div style={{ color: COLORS.muted, textAlign: "center", marginTop: 40 }}>{t.nothingFound}</div>
                : explorePosts.map(p => <PostCard key={p.id} post={p} onLike={handleLike} onComment={handleComment} />)}
            </>
          )}

          {tab === "friends" && (
            <FriendsTab user={user} friends={friends} requests={requests} sentRequests={sentRequests}
              onAccept={handleAccept} onDecline={handleDecline} onConnect={handleConnect}
              onCancelRequest={handleCancelRequest} showToast={showToast} />
          )}

          {tab === "messages" && <MessagesTab />}

          {tab === "profile" && (
            <>
              <div style={{ background: "#111", border: `2px solid ${COLORS.blue}`, boxShadow: `4px 4px 0 ${COLORS.blue}`, marginBottom: 14, overflow: "hidden" }}>
                <div style={{ height: 4, display: "flex" }}>{ACCENTS.map(c => <div key={c} style={{ flex: 1, background: c }} />)}</div>
                <div style={{ height: 56, background: `linear-gradient(135deg,${COLORS.blue}44,${COLORS.yellow}22)`, position: "relative" }}>
                  <button onClick={() => setShowEditProfile(true)} style={{ position: "absolute", top: 7, right: 9, display: "flex", alignItems: "center", gap: 4, background: "rgba(0,0,0,0.6)", border: `1px solid ${COLORS.blue}`, color: COLORS.blue, fontSize: 10, fontWeight: 700, padding: "4px 9px", cursor: "pointer" }}>
                    <Ic.Edit color={COLORS.blue} /> {t.edit}
                  </button>
                </div>
                <div style={{ padding: "0 14px 14px" }}>
                  <div style={{ marginTop: -28, marginBottom: 8 }}><Avatar avatar={user.avatar} size={60} border={3} borderColor={COLORS.blue} /></div>
                  <div style={{ fontWeight: 900, fontSize: 17, color: "#fff" }}>{user.name}</div>
                  <div style={{ color: COLORS.muted, fontSize: 12, marginBottom: 5 }}>{user.handle}</div>
                  {user.location && <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 5 }}><Ic.Pin color={COLORS.yellow} /><span style={{ fontSize: 12, color: COLORS.yellow, fontWeight: 600 }}>{user.location}</span></div>}
                  {user.about && <div style={{ fontSize: 12, color: "#ccc", lineHeight: 1.5, marginBottom: 10, padding: "7px 9px", background: "#0d0d0d", borderLeft: `3px solid ${COLORS.blue}` }}>{user.about}</div>}
                  <div style={{ display: "flex", borderTop: "1px solid #1e1e1e", paddingTop: 9, marginTop: 4 }}>
                    {[{ label: t.posts, val: myPosts.length, color: COLORS.yellow }, { label: t.likes, val: myPosts.reduce((a, p) => a + p.likes, 0), color: COLORS.green }, { label: t.friendsCount, val: friends.length, color: COLORS.red }].map(({ label, val, color }) => (
                      <div key={label} style={{ flex: 1, textAlign: "center" }}>
                        <div style={{ fontWeight: 900, fontSize: 18, color }}>{val}</div>
                        <div style={{ fontSize: 9, color: COLORS.muted, letterSpacing: 0.5 }}>{label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              {myPosts.length === 0
                ? <div style={{ color: COLORS.muted, textAlign: "center", marginTop: 24, fontSize: 13 }}>{t.noPostsProfile}</div>
                : myPosts.map(p => <PostCard key={p.id} post={p} onLike={handleLike} onComment={handleComment} />)}
            </>
          )}
        </div>

        <button onClick={() => setShowCompose(true)} style={{ position: "fixed", bottom: 76, right: 18, width: 52, height: 52, background: COLORS.yellow, border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", boxShadow: `4px 4px 0 ${COLORS.red}`, zIndex: 40 }}
          onMouseDown={e => e.currentTarget.style.transform = "translate(2px,2px)"}
          onMouseUp={e => e.currentTarget.style.transform = ""}>
          <Ic.Plus />
        </button>

        <div style={{ position: "fixed", bottom: 0, left: 0, right: 0, background: "#0a0a0a", borderTop: "2px solid #1a1a1a", display: "flex", zIndex: 50, height: 58 }}>
          {navItems.map(item => (
            <button key={item.id} onClick={() => { setTab(item.id); if (item.id === "friends") setNotifCount(0); }}
              style={{ flex: 1, background: "transparent", border: "none", cursor: "pointer", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 2, borderTop: tab === item.id ? `3px solid ${item.color}` : "3px solid transparent", position: "relative" }}>
              {item.icon}
              {item.badge > 0 && <div style={{ position: "absolute", top: 6, right: "calc(50% - 18px)", width: 14, height: 14, background: COLORS.red, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 8, fontWeight: 900, color: "#fff" }}>{item.badge}</div>}
              <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: 0.3, color: tab === item.id ? item.color : COLORS.muted }}>{item.label}</span>
            </button>
          ))}
        </div>

        {showCompose && <ComposeModal user={user} onClose={() => setShowCompose(false)} onPost={handlePost} />}
        {showEditProfile && <EditProfileModal user={user} onClose={() => setShowEditProfile(false)} onSave={handleSaveProfile} />}
        {showLangPicker && <LangPicker current={lang} onSelect={setLang} onClose={() => setShowLangPicker(false)} />}
      </div>
    </LangCtx.Provider>
  );
}
