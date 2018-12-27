/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

static const SshRexParseMap syntax_egrep =
{
  /* The standard map. */
  {
    SSH_REX_P_EOI,              /* NUL (0) */
    SSH_REX_P_LITERAL,          /* ^A (1) */
    SSH_REX_P_LITERAL,          /* ^B (2) */
    SSH_REX_P_LITERAL,          /* ^C (3) */
    SSH_REX_P_LITERAL,          /* ^D (4) */
    SSH_REX_P_LITERAL,          /* ^E (5) */
    SSH_REX_P_LITERAL,          /* ^F (6) */
    SSH_REX_P_LITERAL,          /* BELL (7) */
    SSH_REX_P_LITERAL,          /* BACKSPACE (8) */
    SSH_REX_P_LITERAL,          /* TAB (9) */
    SSH_REX_P_LITERAL,          /* NEWLINE, LINE FEED (10) */
    SSH_REX_P_LITERAL,          /* ^K (11) */
    SSH_REX_P_LITERAL,          /* ^L (12) */
    SSH_REX_P_LITERAL,          /* CARRIAGE RETURN (13) */
    SSH_REX_P_LITERAL,          /* ^N (14) */
    SSH_REX_P_LITERAL,          /* ^O (15) */
    SSH_REX_P_LITERAL,          /* ^P (16) */
    SSH_REX_P_LITERAL,          /* ^Q (17) */
    SSH_REX_P_LITERAL,          /* ^R (18) */
    SSH_REX_P_LITERAL,          /* ^S (19) */
    SSH_REX_P_LITERAL,          /* ^T (20) */
    SSH_REX_P_LITERAL,          /* ^U (21) */
    SSH_REX_P_LITERAL,          /* ^V (22) */
    SSH_REX_P_LITERAL,          /* ^W (23) */
    SSH_REX_P_LITERAL,          /* ^X (24) */
    SSH_REX_P_LITERAL,          /* ^Y (25) */
    SSH_REX_P_LITERAL,          /* ^Z (26) */
    SSH_REX_P_LITERAL,          /* ^[ (27) */
    SSH_REX_P_LITERAL,          /* ^\ (28) */
    SSH_REX_P_LITERAL,          /* ^] (29) */
    SSH_REX_P_LITERAL,          /* ^^ (30) */
    SSH_REX_P_LITERAL,          /* ^_ (31) */
    SSH_REX_P_LITERAL,          /*   (32) */
    SSH_REX_P_LITERAL,          /* ! (33) */
    SSH_REX_P_LITERAL,          /* " (34) */
    SSH_REX_P_LITERAL,          /* # (35) */
    SSH_REX_P_PCNFA_LINE_END,   /* $ (36) */
    SSH_REX_P_LITERAL,          /* % (37) */
    SSH_REX_P_LITERAL,          /* & (38) */
    SSH_REX_P_LITERAL,          /* ' (39) */
    SSH_REX_P_START_SUBEXPR,    /* ( (40) */
    SSH_REX_P_END_SUBEXPR,      /* ) (41) */
    SSH_REX_P_STAR,             /* * (42) */
    SSH_REX_P_PLUS,             /* + (43) */
    SSH_REX_P_LITERAL,          /* , (44) */
    SSH_REX_P_LITERAL,          /* - (45) */
    SSH_REX_P_PDC_NOT_NEWLINE,  /* . (46) */
    SSH_REX_P_LITERAL,          /* / (47) */
    SSH_REX_P_LITERAL,          /* 0 (48) */
    SSH_REX_P_LITERAL,          /* 1 (49) */
    SSH_REX_P_LITERAL,          /* 2 (50) */
    SSH_REX_P_LITERAL,          /* 3 (51) */
    SSH_REX_P_LITERAL,          /* 4 (52) */
    SSH_REX_P_LITERAL,          /* 5 (53) */
    SSH_REX_P_LITERAL,          /* 6 (54) */
    SSH_REX_P_LITERAL,          /* 7 (55) */
    SSH_REX_P_LITERAL,          /* 8 (56) */
    SSH_REX_P_LITERAL,          /* 9 (57) */
    SSH_REX_P_LITERAL,          /* : (58) */
    SSH_REX_P_LITERAL,          /* ; (59) */
    SSH_REX_P_LITERAL,          /* < (60) */
    SSH_REX_P_LITERAL,          /* = (61) */
    SSH_REX_P_LITERAL,          /* > (62) */
    SSH_REX_P_OPTIONAL,         /* ? (63) */
    SSH_REX_P_LITERAL,          /* @ (64) */
    SSH_REX_P_LITERAL,          /* A (65) */
    SSH_REX_P_LITERAL,          /* B (66) */
    SSH_REX_P_LITERAL,          /* C (67) */
    SSH_REX_P_LITERAL,          /* D (68) */
    SSH_REX_P_LITERAL,          /* E (69) */
    SSH_REX_P_LITERAL,          /* F (70) */
    SSH_REX_P_LITERAL,          /* G (71) */
    SSH_REX_P_LITERAL,          /* H (72) */
    SSH_REX_P_LITERAL,          /* I (73) */
    SSH_REX_P_LITERAL,          /* J (74) */
    SSH_REX_P_LITERAL,          /* K (75) */
    SSH_REX_P_LITERAL,          /* L (76) */
    SSH_REX_P_LITERAL,          /* M (77) */
    SSH_REX_P_LITERAL,          /* N (78) */
    SSH_REX_P_LITERAL,          /* O (79) */
    SSH_REX_P_LITERAL,          /* P (80) */
    SSH_REX_P_LITERAL,          /* Q (81) */
    SSH_REX_P_LITERAL,          /* R (82) */
    SSH_REX_P_LITERAL,          /* S (83) */
    SSH_REX_P_LITERAL,          /* T (84) */
    SSH_REX_P_LITERAL,          /* U (85) */
    SSH_REX_P_LITERAL,          /* V (86) */
    SSH_REX_P_LITERAL,          /* W (87) */
    SSH_REX_P_LITERAL,          /* X (88) */
    SSH_REX_P_LITERAL,          /* Y (89) */
    SSH_REX_P_LITERAL,          /* Z (90) */
    SSH_REX_P_CHARSET_START,    /* [ (91) */
    SSH_REX_P_ESCAPE,           /* \ (92) */
    SSH_REX_P_LITERAL,          /* ] (93) */
    SSH_REX_P_PCNFA_LINE_START, /* ^ (94) */
    SSH_REX_P_LITERAL,          /* _ (95) */
    SSH_REX_P_LITERAL,          /* ` (96) */
    SSH_REX_P_LITERAL,          /* a (97) */
    SSH_REX_P_LITERAL,          /* b (98) */
    SSH_REX_P_LITERAL,          /* c (99) */
    SSH_REX_P_LITERAL,          /* d (100) */
    SSH_REX_P_LITERAL,          /* e (101) */
    SSH_REX_P_LITERAL,          /* f (102) */
    SSH_REX_P_LITERAL,          /* g (103) */
    SSH_REX_P_LITERAL,          /* h (104) */
    SSH_REX_P_LITERAL,          /* i (105) */
    SSH_REX_P_LITERAL,          /* j (106) */
    SSH_REX_P_LITERAL,          /* k (107) */
    SSH_REX_P_LITERAL,          /* l (108) */
    SSH_REX_P_LITERAL,          /* m (109) */
    SSH_REX_P_LITERAL,          /* n (110) */
    SSH_REX_P_LITERAL,          /* o (111) */
    SSH_REX_P_LITERAL,          /* p (112) */
    SSH_REX_P_LITERAL,          /* q (113) */
    SSH_REX_P_LITERAL,          /* r (114) */
    SSH_REX_P_LITERAL,          /* s (115) */
    SSH_REX_P_LITERAL,          /* t (116) */
    SSH_REX_P_LITERAL,          /* u (117) */
    SSH_REX_P_LITERAL,          /* v (118) */
    SSH_REX_P_LITERAL,          /* w (119) */
    SSH_REX_P_LITERAL,          /* x (120) */
    SSH_REX_P_LITERAL,          /* y (121) */
    SSH_REX_P_LITERAL,          /* z (122) */
    SSH_REX_P_START_RANGE,      /* { (123) */
    SSH_REX_P_DISJUNCT,         /* | (124) */
    SSH_REX_P_END_RANGE,        /* } (125) */
    SSH_REX_P_LITERAL,          /* ~ (126) */
    SSH_REX_P_LITERAL,          /* DELETE (127) */
    SSH_REX_P_LITERAL,          /* (128) */
    SSH_REX_P_LITERAL,          /* (129) */
    SSH_REX_P_LITERAL,          /* (130) */
    SSH_REX_P_LITERAL,          /* (131) */
    SSH_REX_P_LITERAL,          /* (132) */
    SSH_REX_P_LITERAL,          /* (133) */
    SSH_REX_P_LITERAL,          /* (134) */
    SSH_REX_P_LITERAL,          /* (135) */
    SSH_REX_P_LITERAL,          /* (136) */
    SSH_REX_P_LITERAL,          /* (137) */
    SSH_REX_P_LITERAL,          /* (138) */
    SSH_REX_P_LITERAL,          /* (139) */
    SSH_REX_P_LITERAL,          /* (140) */
    SSH_REX_P_LITERAL,          /* (141) */
    SSH_REX_P_LITERAL,          /* (142) */
    SSH_REX_P_LITERAL,          /* (143) */
    SSH_REX_P_LITERAL,          /* (144) */
    SSH_REX_P_LITERAL,          /* (145) */
    SSH_REX_P_LITERAL,          /* (146) */
    SSH_REX_P_LITERAL,          /* (147) */
    SSH_REX_P_LITERAL,          /* (148) */
    SSH_REX_P_LITERAL,          /* (149) */
    SSH_REX_P_LITERAL,          /* (150) */
    SSH_REX_P_LITERAL,          /* (151) */
    SSH_REX_P_LITERAL,          /* (152) */
    SSH_REX_P_LITERAL,          /* (153) */
    SSH_REX_P_LITERAL,          /* (154) */
    SSH_REX_P_LITERAL,          /* (155) */
    SSH_REX_P_LITERAL,          /* (156) */
    SSH_REX_P_LITERAL,          /* (157) */
    SSH_REX_P_LITERAL,          /* (158) */
    SSH_REX_P_LITERAL,          /* (159) */
    SSH_REX_P_LITERAL,          /* (160) */
    SSH_REX_P_LITERAL,          /* (161) */
    SSH_REX_P_LITERAL,          /* (162) */
    SSH_REX_P_LITERAL,          /* (163) */
    SSH_REX_P_LITERAL,          /* (164) */
    SSH_REX_P_LITERAL,          /* (165) */
    SSH_REX_P_LITERAL,          /* (166) */
    SSH_REX_P_LITERAL,          /* (167) */
    SSH_REX_P_LITERAL,          /* (168) */
    SSH_REX_P_LITERAL,          /* (169) */
    SSH_REX_P_LITERAL,          /* (170) */
    SSH_REX_P_LITERAL,          /* (171) */
    SSH_REX_P_LITERAL,          /* (172) */
    SSH_REX_P_LITERAL,          /* (173) */
    SSH_REX_P_LITERAL,          /* (174) */
    SSH_REX_P_LITERAL,          /* (175) */
    SSH_REX_P_LITERAL,          /* (176) */
    SSH_REX_P_LITERAL,          /* (177) */
    SSH_REX_P_LITERAL,          /* (178) */
    SSH_REX_P_LITERAL,          /* (179) */
    SSH_REX_P_LITERAL,          /* (180) */
    SSH_REX_P_LITERAL,          /* (181) */
    SSH_REX_P_LITERAL,          /* (182) */
    SSH_REX_P_LITERAL,          /* (183) */
    SSH_REX_P_LITERAL,          /* (184) */
    SSH_REX_P_LITERAL,          /* (185) */
    SSH_REX_P_LITERAL,          /* (186) */
    SSH_REX_P_LITERAL,          /* (187) */
    SSH_REX_P_LITERAL,          /* (188) */
    SSH_REX_P_LITERAL,          /* (189) */
    SSH_REX_P_LITERAL,          /* (190) */
    SSH_REX_P_LITERAL,          /* (191) */
    SSH_REX_P_LITERAL,          /* (192) */
    SSH_REX_P_LITERAL,          /* (193) */
    SSH_REX_P_LITERAL,          /* (194) */
    SSH_REX_P_LITERAL,          /* (195) */
    SSH_REX_P_LITERAL,          /* (196) */
    SSH_REX_P_LITERAL,          /* (197) */
    SSH_REX_P_LITERAL,          /* (198) */
    SSH_REX_P_LITERAL,          /* (199) */
    SSH_REX_P_LITERAL,          /* (200) */
    SSH_REX_P_LITERAL,          /* (201) */
    SSH_REX_P_LITERAL,          /* (202) */
    SSH_REX_P_LITERAL,          /* (203) */
    SSH_REX_P_LITERAL,          /* (204) */
    SSH_REX_P_LITERAL,          /* (205) */
    SSH_REX_P_LITERAL,          /* (206) */
    SSH_REX_P_LITERAL,          /* (207) */
    SSH_REX_P_LITERAL,          /* (208) */
    SSH_REX_P_LITERAL,          /* (209) */
    SSH_REX_P_LITERAL,          /* (210) */
    SSH_REX_P_LITERAL,          /* (211) */
    SSH_REX_P_LITERAL,          /* (212) */
    SSH_REX_P_LITERAL,          /* (213) */
    SSH_REX_P_LITERAL,          /* (214) */
    SSH_REX_P_LITERAL,          /* (215) */
    SSH_REX_P_LITERAL,          /* (216) */
    SSH_REX_P_LITERAL,          /* (217) */
    SSH_REX_P_LITERAL,          /* (218) */
    SSH_REX_P_LITERAL,          /* (219) */
    SSH_REX_P_LITERAL,          /* (220) */
    SSH_REX_P_LITERAL,          /* (221) */
    SSH_REX_P_LITERAL,          /* (222) */
    SSH_REX_P_LITERAL,          /* (223) */
    SSH_REX_P_LITERAL,          /* (224) */
    SSH_REX_P_LITERAL,          /* (225) */
    SSH_REX_P_LITERAL,          /* (226) */
    SSH_REX_P_LITERAL,          /* (227) */
    SSH_REX_P_LITERAL,          /* (228) */
    SSH_REX_P_LITERAL,          /* (229) */
    SSH_REX_P_LITERAL,          /* (230) */
    SSH_REX_P_LITERAL,          /* (231) */
    SSH_REX_P_LITERAL,          /* (232) */
    SSH_REX_P_LITERAL,          /* (233) */
    SSH_REX_P_LITERAL,          /* (234) */
    SSH_REX_P_LITERAL,          /* (235) */
    SSH_REX_P_LITERAL,          /* (236) */
    SSH_REX_P_LITERAL,          /* (237) */
    SSH_REX_P_LITERAL,          /* (238) */
    SSH_REX_P_LITERAL,          /* (239) */
    SSH_REX_P_LITERAL,          /* (240) */
    SSH_REX_P_LITERAL,          /* (241) */
    SSH_REX_P_LITERAL,          /* (242) */
    SSH_REX_P_LITERAL,          /* (243) */
    SSH_REX_P_LITERAL,          /* (244) */
    SSH_REX_P_LITERAL,          /* (245) */
    SSH_REX_P_LITERAL,          /* (246) */
    SSH_REX_P_LITERAL,          /* (247) */
    SSH_REX_P_LITERAL,          /* (248) */
    SSH_REX_P_LITERAL,          /* (249) */
    SSH_REX_P_LITERAL,          /* (250) */
    SSH_REX_P_LITERAL,          /* (251) */
    SSH_REX_P_LITERAL,          /* (252) */
    SSH_REX_P_LITERAL,          /* (253) */
    SSH_REX_P_LITERAL,          /* (254) */
    SSH_REX_P_LITERAL,          /* (255) */
  },

                /* The escape map. */
  {
    SSH_REX_P_ERROR,            /* NUL (0) */
    SSH_REX_P_LITERAL,          /* ^A (1) */
    SSH_REX_P_LITERAL,          /* ^B (2) */
    SSH_REX_P_LITERAL,          /* ^C (3) */
    SSH_REX_P_LITERAL,          /* ^D (4) */
    SSH_REX_P_LITERAL,          /* ^E (5) */
    SSH_REX_P_LITERAL,          /* ^F (6) */
    SSH_REX_P_LITERAL,          /* BELL (7) */
    SSH_REX_P_LITERAL,          /* BACKSPACE (8) */
    SSH_REX_P_LITERAL,          /* TAB (9) */
    SSH_REX_P_LITERAL,          /* NEWLINE, LINE FEED (10) */
    SSH_REX_P_LITERAL,          /* ^K (11) */
    SSH_REX_P_LITERAL,          /* ^L (12) */
    SSH_REX_P_LITERAL,          /* CARRIAGE RETURN (13) */
    SSH_REX_P_LITERAL,          /* ^N (14) */
    SSH_REX_P_LITERAL,          /* ^O (15) */
    SSH_REX_P_LITERAL,          /* ^P (16) */
    SSH_REX_P_LITERAL,          /* ^Q (17) */
    SSH_REX_P_LITERAL,          /* ^R (18) */
    SSH_REX_P_LITERAL,          /* ^S (19) */
    SSH_REX_P_LITERAL,          /* ^T (20) */
    SSH_REX_P_LITERAL,          /* ^U (21) */
    SSH_REX_P_LITERAL,          /* ^V (22) */
    SSH_REX_P_LITERAL,          /* ^W (23) */
    SSH_REX_P_LITERAL,          /* ^X (24) */
    SSH_REX_P_LITERAL,          /* ^Y (25) */
    SSH_REX_P_LITERAL,          /* ^Z (26) */
    SSH_REX_P_LITERAL,          /* ^[ (27) */
    SSH_REX_P_LITERAL,          /* ^\ (28) */
    SSH_REX_P_LITERAL,          /* ^] (29) */
    SSH_REX_P_LITERAL,          /* ^^ (30) */
    SSH_REX_P_LITERAL,          /* ^_ (31) */
    SSH_REX_P_LITERAL,          /*   (32) */
    SSH_REX_P_LITERAL,          /* ! (33) */
    SSH_REX_P_LITERAL,          /* " (34) */
    SSH_REX_P_LITERAL,          /* # (35) */
    SSH_REX_P_LITERAL,          /* $ (36) */
    SSH_REX_P_LITERAL,          /* % (37) */
    SSH_REX_P_LITERAL,          /* & (38) */
    SSH_REX_P_LITERAL,          /* ' (39) */
    SSH_REX_P_LITERAL,          /* ( (40) */
    SSH_REX_P_LITERAL,          /* ) (41) */
    SSH_REX_P_LITERAL,          /* * (42) */
    SSH_REX_P_LITERAL,          /* + (43) */
    SSH_REX_P_LITERAL,          /* , (44) */
    SSH_REX_P_LITERAL,          /* - (45) */
    SSH_REX_P_LITERAL,          /* . (46) */
    SSH_REX_P_LITERAL,          /* / (47) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 0 (48) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 1 (49) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 2 (50) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 3 (51) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 4 (52) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 5 (53) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 6 (54) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 7 (55) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 8 (56) */
    SSH_REX_P_NUMERIC_LITERAL,  /* 9 (57) */
    SSH_REX_P_LITERAL,          /* : (58) */
    SSH_REX_P_LITERAL,          /* ; (59) */
    SSH_REX_P_PCNFA_WORD_START,  /* < (60) */
    SSH_REX_P_LITERAL,          /* = (61) */
    SSH_REX_P_PCNFA_WORD_END,    /* > (62) */
    SSH_REX_P_LITERAL,          /* ? (63) */
    SSH_REX_P_LITERAL,          /* @ (64) */
    SSH_REX_P_LITERAL,          /* A (65) */
    SSH_REX_P_PCNFA_NWORD_BOUNDARY, /* B (66) */
    SSH_REX_P_LITERAL,          /* C (67) */
    SSH_REX_P_LITERAL,          /* D (68) */
    SSH_REX_P_LITERAL,          /* E (69) */
    SSH_REX_P_LITERAL,          /* F (70) */
    SSH_REX_P_LITERAL,          /* G (71) */
    SSH_REX_P_LITERAL,          /* H (72) */
    SSH_REX_P_LITERAL,          /* I (73) */
    SSH_REX_P_LITERAL,          /* J (74) */
    SSH_REX_P_LITERAL,          /* K (75) */
    SSH_REX_P_LITERAL,          /* L (76) */
    SSH_REX_P_LITERAL,          /* M (77) */
    SSH_REX_P_LITERAL,          /* N (78) */
    SSH_REX_P_LITERAL,          /* O (79) */
    SSH_REX_P_LITERAL,          /* P (80) */
    SSH_REX_P_LITERAL,          /* Q (81) */
    SSH_REX_P_LITERAL,          /* R (82) */
    SSH_REX_P_LITERAL,          /* S (83) */
    SSH_REX_P_LITERAL,          /* T (84) */
    SSH_REX_P_LITERAL,          /* U (85) */
    SSH_REX_P_LITERAL,          /* V (86) */
    SSH_REX_P_PDC_NWORD,        /* W (87) */
    SSH_REX_P_LITERAL,          /* X (88) */
    SSH_REX_P_LITERAL,          /* Y (89) */
    SSH_REX_P_LITERAL,          /* Z (90) */
    SSH_REX_P_LITERAL,          /* [ (91) */
    SSH_REX_P_LITERAL,          /* \ (92) */
    SSH_REX_P_LITERAL,          /* ] (93) */
    SSH_REX_P_LITERAL,          /* ^ (94) */
    SSH_REX_P_LITERAL,          /* _ (95) */
    SSH_REX_P_LITERAL,          /* ` (96) */
    SSH_REX_P_LITERAL_ALARM,    /* a (97) */
    SSH_REX_P_PCNFA_WORD_BOUNDARY, /* b (98) */
    SSH_REX_P_LITERAL,          /* c (99) */
    SSH_REX_P_LITERAL,          /* d (100) */
    SSH_REX_P_LITERAL_ESCAPE,   /* e (101) */
    SSH_REX_P_LITERAL_LINE_FEED,/* f (102) */
    SSH_REX_P_LITERAL,          /* g (103) */
    SSH_REX_P_LITERAL,          /* h (104) */
    SSH_REX_P_LITERAL,          /* i (105) */
    SSH_REX_P_LITERAL,          /* j (106) */
    SSH_REX_P_LITERAL,          /* k (107) */
    SSH_REX_P_LITERAL,          /* l (108) */
    SSH_REX_P_LITERAL,          /* m (109) */
    SSH_REX_P_LITERAL_NEWLINE,  /* n (110) */
    SSH_REX_P_LITERAL,          /* o (111) */
    SSH_REX_P_LITERAL,          /* p (112) */
    SSH_REX_P_LITERAL,          /* q (113) */
    SSH_REX_P_LITERAL_RETURN,   /* r (114) */
    SSH_REX_P_LITERAL,          /* s (115) */
    SSH_REX_P_LITERAL_TAB,      /* t (116) */
    SSH_REX_P_LITERAL,          /* u (117) */
    SSH_REX_P_LITERAL,          /* v (118) */
    SSH_REX_P_PDC_WORD,         /* w (119) */
    SSH_REX_P_HEX_LITERAL,      /* x (120) */
    SSH_REX_P_LITERAL,          /* y (121) */
    SSH_REX_P_LITERAL,          /* z (122) */
    SSH_REX_P_LITERAL,          /* { (123) */
    SSH_REX_P_LITERAL,          /* | (124) */
    SSH_REX_P_LITERAL,          /* } (125) */
    SSH_REX_P_LITERAL,          /* ~ (126) */
    SSH_REX_P_LITERAL,          /* DELETE (127) */
    SSH_REX_P_LITERAL,          /* (128) */
    SSH_REX_P_LITERAL,          /* (129) */
    SSH_REX_P_LITERAL,          /* (130) */
    SSH_REX_P_LITERAL,          /* (131) */
    SSH_REX_P_LITERAL,          /* (132) */
    SSH_REX_P_LITERAL,          /* (133) */
    SSH_REX_P_LITERAL,          /* (134) */
    SSH_REX_P_LITERAL,          /* (135) */
    SSH_REX_P_LITERAL,          /* (136) */
    SSH_REX_P_LITERAL,          /* (137) */
    SSH_REX_P_LITERAL,          /* (138) */
    SSH_REX_P_LITERAL,          /* (139) */
    SSH_REX_P_LITERAL,          /* (140) */
    SSH_REX_P_LITERAL,          /* (141) */
    SSH_REX_P_LITERAL,          /* (142) */
    SSH_REX_P_LITERAL,          /* (143) */
    SSH_REX_P_LITERAL,          /* (144) */
    SSH_REX_P_LITERAL,          /* (145) */
    SSH_REX_P_LITERAL,          /* (146) */
    SSH_REX_P_LITERAL,          /* (147) */
    SSH_REX_P_LITERAL,          /* (148) */
    SSH_REX_P_LITERAL,          /* (149) */
    SSH_REX_P_LITERAL,          /* (150) */
    SSH_REX_P_LITERAL,          /* (151) */
    SSH_REX_P_LITERAL,          /* (152) */
    SSH_REX_P_LITERAL,          /* (153) */
    SSH_REX_P_LITERAL,          /* (154) */
    SSH_REX_P_LITERAL,          /* (155) */
    SSH_REX_P_LITERAL,          /* (156) */
    SSH_REX_P_LITERAL,          /* (157) */
    SSH_REX_P_LITERAL,          /* (158) */
    SSH_REX_P_LITERAL,          /* (159) */
    SSH_REX_P_LITERAL,          /* (160) */
    SSH_REX_P_LITERAL,          /* (161) */
    SSH_REX_P_LITERAL,          /* (162) */
    SSH_REX_P_LITERAL,          /* (163) */
    SSH_REX_P_LITERAL,          /* (164) */
    SSH_REX_P_LITERAL,          /* (165) */
    SSH_REX_P_LITERAL,          /* (166) */
    SSH_REX_P_LITERAL,          /* (167) */
    SSH_REX_P_LITERAL,          /* (168) */
    SSH_REX_P_LITERAL,          /* (169) */
    SSH_REX_P_LITERAL,          /* (170) */
    SSH_REX_P_LITERAL,          /* (171) */
    SSH_REX_P_LITERAL,          /* (172) */
    SSH_REX_P_LITERAL,          /* (173) */
    SSH_REX_P_LITERAL,          /* (174) */
    SSH_REX_P_LITERAL,          /* (175) */
    SSH_REX_P_LITERAL,          /* (176) */
    SSH_REX_P_LITERAL,          /* (177) */
    SSH_REX_P_LITERAL,          /* (178) */
    SSH_REX_P_LITERAL,          /* (179) */
    SSH_REX_P_LITERAL,          /* (180) */
    SSH_REX_P_LITERAL,          /* (181) */
    SSH_REX_P_LITERAL,          /* (182) */
    SSH_REX_P_LITERAL,          /* (183) */
    SSH_REX_P_LITERAL,          /* (184) */
    SSH_REX_P_LITERAL,          /* (185) */
    SSH_REX_P_LITERAL,          /* (186) */
    SSH_REX_P_LITERAL,          /* (187) */
    SSH_REX_P_LITERAL,          /* (188) */
    SSH_REX_P_LITERAL,          /* (189) */
    SSH_REX_P_LITERAL,          /* (190) */
    SSH_REX_P_LITERAL,          /* (191) */
    SSH_REX_P_LITERAL,          /* (192) */
    SSH_REX_P_LITERAL,          /* (193) */
    SSH_REX_P_LITERAL,          /* (194) */
    SSH_REX_P_LITERAL,          /* (195) */
    SSH_REX_P_LITERAL,          /* (196) */
    SSH_REX_P_LITERAL,          /* (197) */
    SSH_REX_P_LITERAL,          /* (198) */
    SSH_REX_P_LITERAL,          /* (199) */
    SSH_REX_P_LITERAL,          /* (200) */
    SSH_REX_P_LITERAL,          /* (201) */
    SSH_REX_P_LITERAL,          /* (202) */
    SSH_REX_P_LITERAL,          /* (203) */
    SSH_REX_P_LITERAL,          /* (204) */
    SSH_REX_P_LITERAL,          /* (205) */
    SSH_REX_P_LITERAL,          /* (206) */
    SSH_REX_P_LITERAL,          /* (207) */
    SSH_REX_P_LITERAL,          /* (208) */
    SSH_REX_P_LITERAL,          /* (209) */
    SSH_REX_P_LITERAL,          /* (210) */
    SSH_REX_P_LITERAL,          /* (211) */
    SSH_REX_P_LITERAL,          /* (212) */
    SSH_REX_P_LITERAL,          /* (213) */
    SSH_REX_P_LITERAL,          /* (214) */
    SSH_REX_P_LITERAL,          /* (215) */
    SSH_REX_P_LITERAL,          /* (216) */
    SSH_REX_P_LITERAL,          /* (217) */
    SSH_REX_P_LITERAL,          /* (218) */
    SSH_REX_P_LITERAL,          /* (219) */
    SSH_REX_P_LITERAL,          /* (220) */
    SSH_REX_P_LITERAL,          /* (221) */
    SSH_REX_P_LITERAL,          /* (222) */
    SSH_REX_P_LITERAL,          /* (223) */
    SSH_REX_P_LITERAL,          /* (224) */
    SSH_REX_P_LITERAL,          /* (225) */
    SSH_REX_P_LITERAL,          /* (226) */
    SSH_REX_P_LITERAL,          /* (227) */
    SSH_REX_P_LITERAL,          /* (228) */
    SSH_REX_P_LITERAL,          /* (229) */
    SSH_REX_P_LITERAL,          /* (230) */
    SSH_REX_P_LITERAL,          /* (231) */
    SSH_REX_P_LITERAL,          /* (232) */
    SSH_REX_P_LITERAL,          /* (233) */
    SSH_REX_P_LITERAL,          /* (234) */
    SSH_REX_P_LITERAL,          /* (235) */
    SSH_REX_P_LITERAL,          /* (236) */
    SSH_REX_P_LITERAL,          /* (237) */
    SSH_REX_P_LITERAL,          /* (238) */
    SSH_REX_P_LITERAL,          /* (239) */
    SSH_REX_P_LITERAL,          /* (240) */
    SSH_REX_P_LITERAL,          /* (241) */
    SSH_REX_P_LITERAL,          /* (242) */
    SSH_REX_P_LITERAL,          /* (243) */
    SSH_REX_P_LITERAL,          /* (244) */
    SSH_REX_P_LITERAL,          /* (245) */
    SSH_REX_P_LITERAL,          /* (246) */
    SSH_REX_P_LITERAL,          /* (247) */
    SSH_REX_P_LITERAL,          /* (248) */
    SSH_REX_P_LITERAL,          /* (249) */
    SSH_REX_P_LITERAL,          /* (250) */
    SSH_REX_P_LITERAL,          /* (251) */
    SSH_REX_P_LITERAL,          /* (252) */
    SSH_REX_P_LITERAL,          /* (253) */
    SSH_REX_P_LITERAL,          /* (254) */
    SSH_REX_P_LITERAL,          /* (255) */
  },

                /* The charset syntax map. */
  {
    SSH_REX_P_ERROR,            /* NUL (0) */
    SSH_REX_P_LITERAL,          /* ^A (1) */
    SSH_REX_P_LITERAL,          /* ^B (2) */
    SSH_REX_P_LITERAL,          /* ^C (3) */
    SSH_REX_P_LITERAL,          /* ^D (4) */
    SSH_REX_P_LITERAL,          /* ^E (5) */
    SSH_REX_P_LITERAL,          /* ^F (6) */
    SSH_REX_P_LITERAL,          /* BELL (7) */
    SSH_REX_P_LITERAL,          /* BACKSPACE (8) */
    SSH_REX_P_LITERAL,          /* TAB (9) */
    SSH_REX_P_LITERAL,          /* NEWLINE, LINE FEED (10) */
    SSH_REX_P_LITERAL,          /* ^K (11) */
    SSH_REX_P_LITERAL,          /* ^L (12) */
    SSH_REX_P_LITERAL,          /* CARRIAGE RETURN (13) */
    SSH_REX_P_LITERAL,          /* ^N (14) */
    SSH_REX_P_LITERAL,          /* ^O (15) */
    SSH_REX_P_LITERAL,          /* ^P (16) */
    SSH_REX_P_LITERAL,          /* ^Q (17) */
    SSH_REX_P_LITERAL,          /* ^R (18) */
    SSH_REX_P_LITERAL,          /* ^S (19) */
    SSH_REX_P_LITERAL,          /* ^T (20) */
    SSH_REX_P_LITERAL,          /* ^U (21) */
    SSH_REX_P_LITERAL,          /* ^V (22) */
    SSH_REX_P_LITERAL,          /* ^W (23) */
    SSH_REX_P_LITERAL,          /* ^X (24) */
    SSH_REX_P_LITERAL,          /* ^Y (25) */
    SSH_REX_P_LITERAL,          /* ^Z (26) */
    SSH_REX_P_LITERAL,          /* ^[ (27) */
    SSH_REX_P_LITERAL,          /* ^\ (28) */
    SSH_REX_P_LITERAL,          /* ^] (29) */
    SSH_REX_P_LITERAL,          /* ^^ (30) */
    SSH_REX_P_LITERAL,          /* ^_ (31) */
    SSH_REX_P_LITERAL,          /*   (32) */
    SSH_REX_P_LITERAL,          /* ! (33) */
    SSH_REX_P_LITERAL,          /* " (34) */
    SSH_REX_P_LITERAL,          /* # (35) */
    SSH_REX_P_LITERAL,          /* $ (36) */
    SSH_REX_P_LITERAL,          /* % (37) */
    SSH_REX_P_LITERAL,          /* & (38) */
    SSH_REX_P_LITERAL,          /* ' (39) */
    SSH_REX_P_LITERAL,          /* ( (40) */
    SSH_REX_P_LITERAL,          /* ) (41) */
    SSH_REX_P_LITERAL,          /* * (42) */
    SSH_REX_P_LITERAL,          /* + (43) */
    SSH_REX_P_LITERAL,          /* , (44) */
    SSH_REX_P_CHARSET_RANGE,    /* - (45) */
    SSH_REX_P_LITERAL,          /* . (46) */
    SSH_REX_P_LITERAL,          /* / (47) */
    SSH_REX_P_LITERAL,          /* 0 (48) */
    SSH_REX_P_LITERAL,          /* 1 (49) */
    SSH_REX_P_LITERAL,          /* 2 (50) */
    SSH_REX_P_LITERAL,          /* 3 (51) */
    SSH_REX_P_LITERAL,          /* 4 (52) */
    SSH_REX_P_LITERAL,          /* 5 (53) */
    SSH_REX_P_LITERAL,          /* 6 (54) */
    SSH_REX_P_LITERAL,          /* 7 (55) */
    SSH_REX_P_LITERAL,          /* 8 (56) */
    SSH_REX_P_LITERAL,          /* 9 (57) */
    SSH_REX_P_LITERAL,          /* : (58) */
    SSH_REX_P_LITERAL,          /* ; (59) */
    SSH_REX_P_LITERAL,          /* < (60) */
    SSH_REX_P_LITERAL,          /* = (61) */
    SSH_REX_P_LITERAL,          /* > (62) */
    SSH_REX_P_LITERAL,          /* ? (63) */
    SSH_REX_P_LITERAL,          /* @ (64) */
    SSH_REX_P_LITERAL,          /* A (65) */
    SSH_REX_P_LITERAL,          /* B (66) */
    SSH_REX_P_LITERAL,          /* C (67) */
    SSH_REX_P_LITERAL,          /* D (68) */
    SSH_REX_P_LITERAL,          /* E (69) */
    SSH_REX_P_LITERAL,          /* F (70) */
    SSH_REX_P_LITERAL,          /* G (71) */
    SSH_REX_P_LITERAL,          /* H (72) */
    SSH_REX_P_LITERAL,          /* I (73) */
    SSH_REX_P_LITERAL,          /* J (74) */
    SSH_REX_P_LITERAL,          /* K (75) */
    SSH_REX_P_LITERAL,          /* L (76) */
    SSH_REX_P_LITERAL,          /* M (77) */
    SSH_REX_P_LITERAL,          /* N (78) */
    SSH_REX_P_LITERAL,          /* O (79) */
    SSH_REX_P_LITERAL,          /* P (80) */
    SSH_REX_P_LITERAL,          /* Q (81) */
    SSH_REX_P_LITERAL,          /* R (82) */
    SSH_REX_P_LITERAL,          /* S (83) */
    SSH_REX_P_LITERAL,          /* T (84) */
    SSH_REX_P_LITERAL,          /* U (85) */
    SSH_REX_P_LITERAL,          /* V (86) */
    SSH_REX_P_LITERAL,          /* W (87) */
    SSH_REX_P_LITERAL,          /* X (88) */
    SSH_REX_P_LITERAL,          /* Y (89) */
    SSH_REX_P_LITERAL,          /* Z (90) */
    SSH_REX_P_LITERAL,          /* [ (91) */
    SSH_REX_P_ESCAPE,           /* \ (92) */
    SSH_REX_P_CHARSET_END,      /* ] (93) */
    SSH_REX_P_CHARSET_COMPLEMENT_IF_FIRST, /* ^ (94) */
    SSH_REX_P_LITERAL,          /* _ (95) */
    SSH_REX_P_LITERAL,          /* ` (96) */
    SSH_REX_P_LITERAL,          /* a (97) */
    SSH_REX_P_LITERAL,          /* b (98) */
    SSH_REX_P_LITERAL,          /* c (99) */
    SSH_REX_P_LITERAL,          /* d (100) */
    SSH_REX_P_LITERAL,          /* e (101) */
    SSH_REX_P_LITERAL,          /* f (102) */
    SSH_REX_P_LITERAL,          /* g (103) */
    SSH_REX_P_LITERAL,          /* h (104) */
    SSH_REX_P_LITERAL,          /* i (105) */
    SSH_REX_P_LITERAL,          /* j (106) */
    SSH_REX_P_LITERAL,          /* k (107) */
    SSH_REX_P_LITERAL,          /* l (108) */
    SSH_REX_P_LITERAL,          /* m (109) */
    SSH_REX_P_LITERAL,          /* n (110) */
    SSH_REX_P_LITERAL,          /* o (111) */
    SSH_REX_P_LITERAL,          /* p (112) */
    SSH_REX_P_LITERAL,          /* q (113) */
    SSH_REX_P_LITERAL,          /* r (114) */
    SSH_REX_P_LITERAL,          /* s (115) */
    SSH_REX_P_LITERAL,          /* t (116) */
    SSH_REX_P_LITERAL,          /* u (117) */
    SSH_REX_P_LITERAL,          /* v (118) */
    SSH_REX_P_LITERAL,          /* w (119) */
    SSH_REX_P_LITERAL,          /* x (120) */
    SSH_REX_P_LITERAL,          /* y (121) */
    SSH_REX_P_LITERAL,          /* z (122) */
    SSH_REX_P_LITERAL,          /* { (123) */
    SSH_REX_P_LITERAL,          /* | (124) */
    SSH_REX_P_LITERAL,          /* } (125) */
    SSH_REX_P_LITERAL,          /* ~ (126) */
    SSH_REX_P_LITERAL,          /* DELETE (127) */
    SSH_REX_P_LITERAL,          /* (128) */
    SSH_REX_P_LITERAL,          /* (129) */
    SSH_REX_P_LITERAL,          /* (130) */
    SSH_REX_P_LITERAL,          /* (131) */
    SSH_REX_P_LITERAL,          /* (132) */
    SSH_REX_P_LITERAL,          /* (133) */
    SSH_REX_P_LITERAL,          /* (134) */
    SSH_REX_P_LITERAL,          /* (135) */
    SSH_REX_P_LITERAL,          /* (136) */
    SSH_REX_P_LITERAL,          /* (137) */
    SSH_REX_P_LITERAL,          /* (138) */
    SSH_REX_P_LITERAL,          /* (139) */
    SSH_REX_P_LITERAL,          /* (140) */
    SSH_REX_P_LITERAL,          /* (141) */
    SSH_REX_P_LITERAL,          /* (142) */
    SSH_REX_P_LITERAL,          /* (143) */
    SSH_REX_P_LITERAL,          /* (144) */
    SSH_REX_P_LITERAL,          /* (145) */
    SSH_REX_P_LITERAL,          /* (146) */
    SSH_REX_P_LITERAL,          /* (147) */
    SSH_REX_P_LITERAL,          /* (148) */
    SSH_REX_P_LITERAL,          /* (149) */
    SSH_REX_P_LITERAL,          /* (150) */
    SSH_REX_P_LITERAL,          /* (151) */
    SSH_REX_P_LITERAL,          /* (152) */
    SSH_REX_P_LITERAL,          /* (153) */
    SSH_REX_P_LITERAL,          /* (154) */
    SSH_REX_P_LITERAL,          /* (155) */
    SSH_REX_P_LITERAL,          /* (156) */
    SSH_REX_P_LITERAL,          /* (157) */
    SSH_REX_P_LITERAL,          /* (158) */
    SSH_REX_P_LITERAL,          /* (159) */
    SSH_REX_P_LITERAL,          /* (160) */
    SSH_REX_P_LITERAL,          /* (161) */
    SSH_REX_P_LITERAL,          /* (162) */
    SSH_REX_P_LITERAL,          /* (163) */
    SSH_REX_P_LITERAL,          /* (164) */
    SSH_REX_P_LITERAL,          /* (165) */
    SSH_REX_P_LITERAL,          /* (166) */
    SSH_REX_P_LITERAL,          /* (167) */
    SSH_REX_P_LITERAL,          /* (168) */
    SSH_REX_P_LITERAL,          /* (169) */
    SSH_REX_P_LITERAL,          /* (170) */
    SSH_REX_P_LITERAL,          /* (171) */
    SSH_REX_P_LITERAL,          /* (172) */
    SSH_REX_P_LITERAL,          /* (173) */
    SSH_REX_P_LITERAL,          /* (174) */
    SSH_REX_P_LITERAL,          /* (175) */
    SSH_REX_P_LITERAL,          /* (176) */
    SSH_REX_P_LITERAL,          /* (177) */
    SSH_REX_P_LITERAL,          /* (178) */
    SSH_REX_P_LITERAL,          /* (179) */
    SSH_REX_P_LITERAL,          /* (180) */
    SSH_REX_P_LITERAL,          /* (181) */
    SSH_REX_P_LITERAL,          /* (182) */
    SSH_REX_P_LITERAL,          /* (183) */
    SSH_REX_P_LITERAL,          /* (184) */
    SSH_REX_P_LITERAL,          /* (185) */
    SSH_REX_P_LITERAL,          /* (186) */
    SSH_REX_P_LITERAL,          /* (187) */
    SSH_REX_P_LITERAL,          /* (188) */
    SSH_REX_P_LITERAL,          /* (189) */
    SSH_REX_P_LITERAL,          /* (190) */
    SSH_REX_P_LITERAL,          /* (191) */
    SSH_REX_P_LITERAL,          /* (192) */
    SSH_REX_P_LITERAL,          /* (193) */
    SSH_REX_P_LITERAL,          /* (194) */
    SSH_REX_P_LITERAL,          /* (195) */
    SSH_REX_P_LITERAL,          /* (196) */
    SSH_REX_P_LITERAL,          /* (197) */
    SSH_REX_P_LITERAL,          /* (198) */
    SSH_REX_P_LITERAL,          /* (199) */
    SSH_REX_P_LITERAL,          /* (200) */
    SSH_REX_P_LITERAL,          /* (201) */
    SSH_REX_P_LITERAL,          /* (202) */
    SSH_REX_P_LITERAL,          /* (203) */
    SSH_REX_P_LITERAL,          /* (204) */
    SSH_REX_P_LITERAL,          /* (205) */
    SSH_REX_P_LITERAL,          /* (206) */
    SSH_REX_P_LITERAL,          /* (207) */
    SSH_REX_P_LITERAL,          /* (208) */
    SSH_REX_P_LITERAL,          /* (209) */
    SSH_REX_P_LITERAL,          /* (210) */
    SSH_REX_P_LITERAL,          /* (211) */
    SSH_REX_P_LITERAL,          /* (212) */
    SSH_REX_P_LITERAL,          /* (213) */
    SSH_REX_P_LITERAL,          /* (214) */
    SSH_REX_P_LITERAL,          /* (215) */
    SSH_REX_P_LITERAL,          /* (216) */
    SSH_REX_P_LITERAL,          /* (217) */
    SSH_REX_P_LITERAL,          /* (218) */
    SSH_REX_P_LITERAL,          /* (219) */
    SSH_REX_P_LITERAL,          /* (220) */
    SSH_REX_P_LITERAL,          /* (221) */
    SSH_REX_P_LITERAL,          /* (222) */
    SSH_REX_P_LITERAL,          /* (223) */
    SSH_REX_P_LITERAL,          /* (224) */
    SSH_REX_P_LITERAL,          /* (225) */
    SSH_REX_P_LITERAL,          /* (226) */
    SSH_REX_P_LITERAL,          /* (227) */
    SSH_REX_P_LITERAL,          /* (228) */
    SSH_REX_P_LITERAL,          /* (229) */
    SSH_REX_P_LITERAL,          /* (230) */
    SSH_REX_P_LITERAL,          /* (231) */
    SSH_REX_P_LITERAL,          /* (232) */
    SSH_REX_P_LITERAL,          /* (233) */
    SSH_REX_P_LITERAL,          /* (234) */
    SSH_REX_P_LITERAL,          /* (235) */
    SSH_REX_P_LITERAL,          /* (236) */
    SSH_REX_P_LITERAL,          /* (237) */
    SSH_REX_P_LITERAL,          /* (238) */
    SSH_REX_P_LITERAL,          /* (239) */
    SSH_REX_P_LITERAL,          /* (240) */
    SSH_REX_P_LITERAL,          /* (241) */
    SSH_REX_P_LITERAL,          /* (242) */
    SSH_REX_P_LITERAL,          /* (243) */
    SSH_REX_P_LITERAL,          /* (244) */
    SSH_REX_P_LITERAL,          /* (245) */
    SSH_REX_P_LITERAL,          /* (246) */
    SSH_REX_P_LITERAL,          /* (247) */
    SSH_REX_P_LITERAL,          /* (248) */
    SSH_REX_P_LITERAL,          /* (249) */
    SSH_REX_P_LITERAL,          /* (250) */
    SSH_REX_P_LITERAL,          /* (251) */
    SSH_REX_P_LITERAL,          /* (252) */
    SSH_REX_P_LITERAL,          /* (253) */
    SSH_REX_P_LITERAL,          /* (254) */
    SSH_REX_P_LITERAL,          /* (255) */
  },

  { { "*?", SSH_REX_P_STAR_LAZY },
    { "+?", SSH_REX_P_PLUS_LAZY },
    { "??", SSH_REX_P_OPTIONAL_LAZY },
    { "}?", SSH_REX_P_END_RANGE_LAZY }
  },

  SSH_REX_PARSE_FLAG_POSIX_CHARSETS
};

