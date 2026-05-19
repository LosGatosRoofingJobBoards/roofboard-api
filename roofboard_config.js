// ─────────────────────────────────────────────────────────────
//  roofboard_config.js  — shared constants for all RoofBoard pages
//  Update this ONE file to change colors, roles, or deck types
//  across the entire system.
// ─────────────────────────────────────────────────────────────

// ── API endpoint ── change after Railway deployment ───────────
const RB_API = 'lgrroofboard-api-production.up.railway.app';

// ── Deck types (fixed list) ───────────────────────────────────
const DECK_TYPES = [
  { value: '',          label: '— None / Unknown —' },
  { value: 'solid_1x',  label: 'Solid 1x' },
  { value: 'skip',      label: 'Skip Sheathing' },
  { value: 'plywood',   label: 'Plywood' },
  { value: 'osb',       label: 'OSB' },
  { value: 'tng',       label: 'T&G' },
];

// ── Backlog categories ────────────────────────────────────────
const BACKLOG_CATEGORIES = [
  { value: 'regular',   label: 'Regular' },
  { value: 'on_hold',   label: 'On Hold' },
  { value: 'jan',  label: 'January' },
  { value: 'feb',  label: 'February' },
  { value: 'mar',  label: 'March' },
  { value: 'apr',  label: 'April' },
  { value: 'may',  label: 'May' },
  { value: 'jun',  label: 'June' },
  { value: 'jul',  label: 'July' },
  { value: 'aug',  label: 'August' },
  { value: 'sep',  label: 'September' },
  { value: 'oct',  label: 'October' },
  { value: 'nov',  label: 'November' },
  { value: 'dec',  label: 'December' },
];

const MONTH_ORDER = ['jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec'];

// ── Roles ─────────────────────────────────────────────────────
const ROLE_LABELS = {
  admin:            'Admin',
  scheduler:        'Scheduler',
  office_staff:     'Office Staff',
  sales:            'Roofing Consultant',
  removal_foreman:  'Removal Foreman',
  supplier:         'Supplier',
};
const ROLE_COLORS = {
  admin:            { bg:'#DEEDFB', text:'#0C447C' },
  scheduler:        { bg:'#E8E6FD', text:'#3C3489' },
  office_staff:     { bg:'#DCF0CC', text:'#27500A' },
  sales:            { bg:'#F8E9C8', text:'#633806' },
  removal_foreman:  { bg:'#FAE0E0', text:'#791F1F' },
  supplier:         { bg:'#f0f0ec', text:'#888'    },
};

// ── Gutter profiles ───────────────────────────────────────────
const GUTTER_PROFILES = {
  '5.5_fascia':        { label:'5½" Fascia',        short:'5½F'  },
  '5.5_curved_fascia': { label:'5½" Curved Fascia',  short:'5½CF' },
  '5_ogee':            { label:'5" Ogee',             short:'5OG'  },
  '6_ogee':            { label:'6" Ogee',             short:'6OG'  },
  '7.5_fascia':        { label:'7½" Fascia',          short:'7½F'  },
};

// ── Gutter materials ──────────────────────────────────────────
const GUTTER_MATERIALS_MAP = {
  aluminum:   { label:'Aluminum',   short:'AL',  bg:'#D6EAF8', text:'#1A5276' },
  steel:      { label:'Steel',      short:'STL', bg:'#EAECEE', text:'#424949' },
  bonderized: { label:'Bonderized', short:'BND', bg:'#F9EBEA', text:'#7B241C' },
};

// ── Layer materials ───────────────────────────────────────────
// (used for roof layer stack — populated dynamically from roof_materials)
// Fallback static list if API unavailable
const LAYER_MATS_FALLBACK = [
  {v:'comp',l:'Comp'},{v:'tile',l:'Tile'},{v:'metal',l:'Metal'},
  {v:'wood',l:'Wood'},{v:'flat',l:'Flat/TPO'},{v:'polymer',l:'Polymer'},{v:'other',l:'Other'}
];

// ── Inspection types ──────────────────────────────────────────
const INSP_TYPES = [
  { value:'tearoff',    label:'Tear-off',    cls:'insp-tearoff'    },
  { value:'nailing',    label:'Nailing',     cls:'insp-nailing'    },
  { value:'inprogress', label:'In-progress', cls:'insp-inprogress' },
  { value:'final',      label:'Final',       cls:'insp-final'      },
];

// ── Approval states ───────────────────────────────────────────
function rbApprovalInfo(s) {
  if(s==='confirmed')    return { label:'✓ Confirmed',    cls:'tag-confirmed',    fullCls:'appr-confirmed'    };
  if(s==='not_approved') return { label:'✗ Not Approved', cls:'tag-not-approved', fullCls:'appr-not-approved' };
  return                        { label:'? Pending',      cls:'tag-pending',      fullCls:'appr-pending'      };
}

// ── Deck label helper ─────────────────────────────────────────
function rbDeckLabel(val) {
  const d = DECK_TYPES.find(x=>x.value===val);
  return d ? d.label : (val||'—');
}

// ── Backlog category label ────────────────────────────────────
function rbCategoryLabel(val) {
  const c = BACKLOG_CATEGORIES.find(x=>x.value===val);
  return c ? c.label : 'Regular';
}

// ── Format date ───────────────────────────────────────────────
function rbFmtD(d) {
  if(!d) return '—';
  const dt = new Date(d+'T00:00:00');
  return isNaN(dt) ? d : dt.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'});
}
function rbFmtFull(d) {
  if(!d) return '—';
  const dt = new Date(d+'T00:00:00');
  return isNaN(dt) ? d : dt.toLocaleDateString('en-US',{weekday:'long',month:'long',day:'numeric',year:'numeric'});
}
