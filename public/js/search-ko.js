(() => {
  // <stdin>
  (() => {
    var index_url = "//localhost:1313/ko/index.json";
    var cmp = new Intl.Collator("en", { numeric: true, sensitivity: "base" }).compare;
    var inf = Infinity;
    var escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    var EXACT_HERE = "eexxaacctt";
    var PUNCT_RE = /\p{P}/gu;
    var LATIN_UPPER = "A-Z";
    var LATIN_LOWER = "a-z";
    var swapAlpha = (str, upper, lower) => str.replace(LATIN_UPPER, upper).replace(LATIN_LOWER, lower);
    var OPTS = {
      // whether regexps use a /u unicode flag
      unicode: false,
      alpha: null,
      // term segmentation & punct/whitespace merging
      interSplit: "[^A-Za-z\\d']+",
      intraSplit: "[a-z][A-Z]",
      // inter bounds that will be used to increase lft2/rgt2 info counters
      interBound: "[^A-Za-z\\d]",
      // intra bounds that will be used to increase lft1/rgt1 info counters
      intraBound: "[A-Za-z]\\d|\\d[A-Za-z]|[a-z][A-Z]",
      // inter-bounds mode
      // 2 = strict (will only match 'man' on whitepace and punct boundaries: Mega Man, Mega_Man, mega.man)
      // 1 = loose  (plus allowance for alpha-num and case-change boundaries: MegaMan, 0007man)
      // 0 = any    (will match 'man' as any substring: megamaniac)
      interLft: 0,
      interRgt: 0,
      // allowance between terms
      interChars: ".",
      interIns: inf,
      // allowance between chars in terms
      intraChars: "[a-z\\d']",
      // internally case-insensitive
      intraIns: null,
      intraContr: "'[a-z]{1,2}\\b",
      // multi-insert or single-error mode
      intraMode: 0,
      // single-error bounds for errors within terms, default requires exact first char
      intraSlice: [1, inf],
      // single-error tolerance toggles
      intraSub: null,
      intraTrn: null,
      intraDel: null,
      // can post-filter matches that are too far apart in distance or length
      // (since intraIns is between each char, it can accum to nonsense matches)
      intraFilt: (term, match, index) => true,
      // should this also accept WIP info?
      // final sorting fn
      sort: (info, haystack, needle) => {
        let {
          idx,
          chars,
          terms,
          interLft2,
          interLft1,
          //	interRgt2,
          //	interRgt1,
          start,
          intraIns,
          interIns
        } = info;
        return idx.map((v, i) => i).sort((ia, ib) => (
          // most contig chars matched
          chars[ib] - chars[ia] || // least char intra-fuzz (most contiguous)
          intraIns[ia] - intraIns[ib] || // most prefix bounds, boosted by full term matches
          terms[ib] + interLft2[ib] + 0.5 * interLft1[ib] - (terms[ia] + interLft2[ia] + 0.5 * interLft1[ia]) || // highest density of match (least span)
          //	span[ia] - span[ib] ||
          // highest density of match (least term inter-fuzz)
          interIns[ia] - interIns[ib] || // earliest start of match
          start[ia] - start[ib] || // alphabetic
          cmp(haystack[idx[ia]], haystack[idx[ib]])
        ));
      }
    };
    var lazyRepeat = (chars, limit) => limit == 0 ? "" : limit == 1 ? chars + "??" : limit == inf ? chars + "*?" : chars + `{0,${limit}}?`;
    var mode2Tpl = "(?:\\b|_)";
    function uFuzzy(opts) {
      opts = Object.assign({}, OPTS, opts);
      let {
        unicode,
        interLft,
        interRgt,
        intraMode,
        intraSlice,
        intraIns,
        intraSub,
        intraTrn,
        intraDel,
        intraContr,
        intraSplit: _intraSplit,
        interSplit: _interSplit,
        intraBound: _intraBound,
        interBound: _interBound,
        intraChars
      } = opts;
      intraIns ??= intraMode;
      intraSub ??= intraMode;
      intraTrn ??= intraMode;
      intraDel ??= intraMode;
      let alpha = opts.letters ?? opts.alpha;
      if (alpha != null) {
        let upper = alpha.toLocaleUpperCase();
        let lower = alpha.toLocaleLowerCase();
        _interSplit = swapAlpha(_interSplit, upper, lower);
        _intraSplit = swapAlpha(_intraSplit, upper, lower);
        _interBound = swapAlpha(_interBound, upper, lower);
        _intraBound = swapAlpha(_intraBound, upper, lower);
        intraChars = swapAlpha(intraChars, upper, lower);
        intraContr = swapAlpha(intraContr, upper, lower);
      }
      let uFlag = unicode ? "u" : "";
      const quotedAny = '".+?"';
      const EXACTS_RE = new RegExp(quotedAny, "gi" + uFlag);
      const NEGS_RE = new RegExp(`(?:\\s+|^)-(?:${intraChars}+|${quotedAny})`, "gi" + uFlag);
      let { intraRules } = opts;
      if (intraRules == null) {
        intraRules = (p) => {
          let _intraSlice = OPTS.intraSlice, _intraIns = 0, _intraSub = 0, _intraTrn = 0, _intraDel = 0;
          if (/[^\d]/.test(p)) {
            let plen = p.length;
            if (plen <= 4) {
              if (plen >= 3) {
                _intraTrn = Math.min(intraTrn, 1);
                if (plen == 4)
                  _intraIns = Math.min(intraIns, 1);
              }
            } else {
              _intraSlice = intraSlice;
              _intraIns = intraIns, _intraSub = intraSub, _intraTrn = intraTrn, _intraDel = intraDel;
            }
          }
          return {
            intraSlice: _intraSlice,
            intraIns: _intraIns,
            intraSub: _intraSub,
            intraTrn: _intraTrn,
            intraDel: _intraDel
          };
        };
      }
      let withIntraSplit = !!_intraSplit;
      let intraSplit = new RegExp(_intraSplit, "g" + uFlag);
      let interSplit = new RegExp(_interSplit, "g" + uFlag);
      let trimRe = new RegExp("^" + _interSplit + "|" + _interSplit + "$", "g" + uFlag);
      let contrsRe = new RegExp(intraContr, "gi" + uFlag);
      const split = (needle) => {
        let exacts = [];
        needle = needle.replace(EXACTS_RE, (m) => {
          exacts.push(m);
          return EXACT_HERE;
        });
        needle = needle.replace(trimRe, "").toLocaleLowerCase();
        if (withIntraSplit)
          needle = needle.replace(intraSplit, (m) => m[0] + " " + m[1]);
        let j = 0;
        return needle.split(interSplit).filter((t) => t != "").map((v) => v === EXACT_HERE ? exacts[j++] : v);
      };
      const NUM_OR_ALPHA_RE = /[^\d]+|\d+/g;
      const prepQuery = (needle, capt = 0, interOR = false) => {
        let parts = split(needle);
        if (parts.length == 0)
          return [];
        let contrs = Array(parts.length).fill("");
        parts = parts.map((p, pi) => p.replace(contrsRe, (m) => {
          contrs[pi] = m;
          return "";
        }));
        let reTpl;
        if (intraMode == 1) {
          reTpl = parts.map((p, pi) => {
            if (p[0] === '"')
              return escapeRegExp(p.slice(1, -1));
            let reTpl2 = "";
            for (let m of p.matchAll(NUM_OR_ALPHA_RE)) {
              let p2 = m[0];
              let {
                intraSlice: intraSlice2,
                intraIns: intraIns2,
                intraSub: intraSub2,
                intraTrn: intraTrn2,
                intraDel: intraDel2
              } = intraRules(p2);
              if (intraIns2 + intraSub2 + intraTrn2 + intraDel2 == 0)
                reTpl2 += p2 + contrs[pi];
              else {
                let [lftIdx, rgtIdx] = intraSlice2;
                let lftChar = p2.slice(0, lftIdx);
                let rgtChar = p2.slice(rgtIdx);
                let chars = p2.slice(lftIdx, rgtIdx);
                if (intraIns2 == 1 && lftChar.length == 1 && lftChar != chars[0])
                  lftChar += "(?!" + lftChar + ")";
                let numChars = chars.length;
                let variants = [p2];
                if (intraSub2) {
                  for (let i = 0; i < numChars; i++)
                    variants.push(lftChar + chars.slice(0, i) + intraChars + chars.slice(i + 1) + rgtChar);
                }
                if (intraTrn2) {
                  for (let i = 0; i < numChars - 1; i++) {
                    if (chars[i] != chars[i + 1])
                      variants.push(lftChar + chars.slice(0, i) + chars[i + 1] + chars[i] + chars.slice(i + 2) + rgtChar);
                  }
                }
                if (intraDel2) {
                  for (let i = 0; i < numChars; i++)
                    variants.push(lftChar + chars.slice(0, i + 1) + "?" + chars.slice(i + 1) + rgtChar);
                }
                if (intraIns2) {
                  let intraInsTpl = lazyRepeat(intraChars, 1);
                  for (let i = 0; i < numChars; i++)
                    variants.push(lftChar + chars.slice(0, i) + intraInsTpl + chars.slice(i) + rgtChar);
                }
                reTpl2 += "(?:" + variants.join("|") + ")" + contrs[pi];
              }
            }
            return reTpl2;
          });
        } else {
          let intraInsTpl = lazyRepeat(intraChars, intraIns);
          if (capt == 2 && intraIns > 0) {
            intraInsTpl = ")(" + intraInsTpl + ")(";
          }
          reTpl = parts.map((p, pi) => p[0] === '"' ? escapeRegExp(p.slice(1, -1)) : p.split("").map((c, i, chars) => {
            if (intraIns == 1 && i == 0 && chars.length > 1 && c != chars[i + 1])
              c += "(?!" + c + ")";
            return c;
          }).join(intraInsTpl) + contrs[pi]);
        }
        let preTpl = interLft == 2 ? mode2Tpl : "";
        let sufTpl = interRgt == 2 ? mode2Tpl : "";
        let interCharsTpl = sufTpl + lazyRepeat(opts.interChars, opts.interIns) + preTpl;
        if (capt > 0) {
          if (interOR) {
            reTpl = preTpl + "(" + reTpl.join(")" + sufTpl + "|" + preTpl + "(") + ")" + sufTpl;
          } else {
            reTpl = "(" + reTpl.join(")(" + interCharsTpl + ")(") + ")";
            reTpl = "(.??" + preTpl + ")" + reTpl + "(" + sufTpl + ".*)";
          }
        } else {
          reTpl = reTpl.join(interCharsTpl);
          reTpl = preTpl + reTpl + sufTpl;
        }
        return [new RegExp(reTpl, "i" + uFlag), parts, contrs];
      };
      const filter = (haystack, needle, idxs) => {
        let [query] = prepQuery(needle);
        if (query == null)
          return null;
        let out = [];
        if (idxs != null) {
          for (let i = 0; i < idxs.length; i++) {
            let idx = idxs[i];
            query.test(haystack[idx]) && out.push(idx);
          }
        } else {
          for (let i = 0; i < haystack.length; i++)
            query.test(haystack[i]) && out.push(i);
        }
        return out;
      };
      let withIntraBound = !!_intraBound;
      let interBound = new RegExp(_interBound, uFlag);
      let intraBound = new RegExp(_intraBound, uFlag);
      const info = (idxs, haystack, needle) => {
        let [query, parts, contrs] = prepQuery(needle, 1);
        let [queryR] = prepQuery(needle, 2);
        let partsLen = parts.length;
        let len = idxs.length;
        let field = Array(len).fill(0);
        let info2 = {
          // idx in haystack
          idx: Array(len),
          // start of match
          start: field.slice(),
          // length of match
          //	span: field.slice(),
          // contiguous chars matched
          chars: field.slice(),
          // contiguous (no fuzz) and bounded terms (intra=0, lft2/1, rgt2/1)
          // excludes terms that are contiguous but have < 2 bounds (substrings)
          terms: field.slice(),
          // cumulative length of unmatched chars (fuzz) within span
          interIns: field.slice(),
          // between terms
          intraIns: field.slice(),
          // within terms
          // interLft/interRgt counters
          interLft2: field.slice(),
          interRgt2: field.slice(),
          interLft1: field.slice(),
          interRgt1: field.slice(),
          ranges: Array(len)
        };
        let mayDiscard = interLft == 1 || interRgt == 1;
        let ii = 0;
        for (let i = 0; i < idxs.length; i++) {
          let mhstr = haystack[idxs[i]];
          let m = mhstr.match(query);
          let start = m.index + m[1].length;
          let idxAcc = start;
          let disc = false;
          let lft2 = 0;
          let lft1 = 0;
          let rgt2 = 0;
          let rgt1 = 0;
          let chars = 0;
          let terms = 0;
          let inter = 0;
          let intra = 0;
          let refine = [];
          for (let j = 0, k = 2; j < partsLen; j++, k += 2) {
            let group = m[k].toLocaleLowerCase();
            let part = parts[j];
            let term = part[0] == '"' ? part.slice(1, -1) : part + contrs[j];
            let termLen = term.length;
            let groupLen = group.length;
            let fullMatch = group == term;
            if (!fullMatch && m[k + 1].length >= termLen) {
              let idxOf = m[k + 1].toLocaleLowerCase().indexOf(term);
              if (idxOf > -1) {
                refine.push(idxAcc, groupLen, idxOf, termLen);
                idxAcc += refineMatch(m, k, idxOf, termLen);
                group = term;
                groupLen = termLen;
                fullMatch = true;
                if (j == 0)
                  start = idxAcc;
              }
            }
            if (mayDiscard || fullMatch) {
              let lftCharIdx = idxAcc - 1;
              let rgtCharIdx = idxAcc + groupLen;
              let isPre = false;
              let isSuf = false;
              if (lftCharIdx == -1 || interBound.test(mhstr[lftCharIdx])) {
                fullMatch && lft2++;
                isPre = true;
              } else {
                if (interLft == 2) {
                  disc = true;
                  break;
                }
                if (withIntraBound && intraBound.test(mhstr[lftCharIdx] + mhstr[lftCharIdx + 1])) {
                  fullMatch && lft1++;
                  isPre = true;
                } else {
                  if (interLft == 1) {
                    let junk = m[k + 1];
                    let junkIdx = idxAcc + groupLen;
                    if (junk.length >= termLen) {
                      let idxOf = 0;
                      let found = false;
                      let re = new RegExp(term, "ig" + uFlag);
                      let m2;
                      while (m2 = re.exec(junk)) {
                        idxOf = m2.index;
                        let charIdx = junkIdx + idxOf;
                        let lftCharIdx2 = charIdx - 1;
                        if (lftCharIdx2 == -1 || interBound.test(mhstr[lftCharIdx2])) {
                          lft2++;
                          found = true;
                          break;
                        } else if (intraBound.test(mhstr[lftCharIdx2] + mhstr[charIdx])) {
                          lft1++;
                          found = true;
                          break;
                        }
                      }
                      if (found) {
                        isPre = true;
                        refine.push(idxAcc, groupLen, idxOf, termLen);
                        idxAcc += refineMatch(m, k, idxOf, termLen);
                        group = term;
                        groupLen = termLen;
                        fullMatch = true;
                        if (j == 0)
                          start = idxAcc;
                      }
                    }
                    if (!isPre) {
                      disc = true;
                      break;
                    }
                  }
                }
              }
              if (rgtCharIdx == mhstr.length || interBound.test(mhstr[rgtCharIdx])) {
                fullMatch && rgt2++;
                isSuf = true;
              } else {
                if (interRgt == 2) {
                  disc = true;
                  break;
                }
                if (withIntraBound && intraBound.test(mhstr[rgtCharIdx - 1] + mhstr[rgtCharIdx])) {
                  fullMatch && rgt1++;
                  isSuf = true;
                } else {
                  if (interRgt == 1) {
                    disc = true;
                    break;
                  }
                }
              }
              if (fullMatch) {
                chars += termLen;
                if (isPre && isSuf)
                  terms++;
              }
            }
            if (groupLen > termLen)
              intra += groupLen - termLen;
            if (j > 0)
              inter += m[k - 1].length;
            if (!opts.intraFilt(term, group, idxAcc)) {
              disc = true;
              break;
            }
            if (j < partsLen - 1)
              idxAcc += groupLen + m[k + 1].length;
          }
          if (!disc) {
            info2.idx[ii] = idxs[i];
            info2.interLft2[ii] = lft2;
            info2.interLft1[ii] = lft1;
            info2.interRgt2[ii] = rgt2;
            info2.interRgt1[ii] = rgt1;
            info2.chars[ii] = chars;
            info2.terms[ii] = terms;
            info2.interIns[ii] = inter;
            info2.intraIns[ii] = intra;
            info2.start[ii] = start;
            let m2 = mhstr.match(queryR);
            let idxAcc2 = m2.index + m2[1].length;
            let refLen = refine.length;
            let ri = refLen > 0 ? 0 : Infinity;
            let lastRi = refLen - 4;
            for (let i2 = 2; i2 < m2.length; ) {
              let len2 = m2[i2].length;
              if (ri <= lastRi && refine[ri] == idxAcc2) {
                let groupLen = refine[ri + 1];
                let idxOf = refine[ri + 2];
                let termLen = refine[ri + 3];
                let j = i2;
                let v = "";
                for (let _len = 0; _len < groupLen; j++) {
                  v += m2[j];
                  _len += m2[j].length;
                }
                m2.splice(i2, j - i2, v);
                idxAcc2 += refineMatch(m2, i2, idxOf, termLen);
                ri += 4;
              } else {
                idxAcc2 += len2;
                i2++;
              }
            }
            idxAcc2 = m2.index + m2[1].length;
            let ranges = info2.ranges[ii] = [];
            let from = idxAcc2;
            let to = idxAcc2;
            for (let i2 = 2; i2 < m2.length; i2++) {
              let len2 = m2[i2].length;
              idxAcc2 += len2;
              if (i2 % 2 == 0)
                to = idxAcc2;
              else if (len2 > 0) {
                ranges.push(from, to);
                from = to = idxAcc2;
              }
            }
            if (to > from)
              ranges.push(from, to);
            ii++;
          }
        }
        if (ii < idxs.length) {
          for (let k in info2)
            info2[k] = info2[k].slice(0, ii);
        }
        return info2;
      };
      const refineMatch = (m, k, idxInNext, termLen) => {
        let prepend = m[k] + m[k + 1].slice(0, idxInNext);
        m[k - 1] += prepend;
        m[k] = m[k + 1].slice(idxInNext, idxInNext + termLen);
        m[k + 1] = m[k + 1].slice(idxInNext + termLen);
        return prepend.length;
      };
      const OOO_TERMS_LIMIT = 5;
      const _search = (haystack, needle, outOfOrder, infoThresh = 1e3, preFiltered) => {
        outOfOrder = !outOfOrder ? 0 : outOfOrder === true ? OOO_TERMS_LIMIT : outOfOrder;
        let needles = null;
        let matches = null;
        let negs = [];
        needle = needle.replace(NEGS_RE, (m) => {
          let neg = m.trim().slice(1);
          neg = neg[0] === '"' ? escapeRegExp(neg.slice(1, -1)) : neg.replace(PUNCT_RE, "");
          if (neg != "")
            negs.push(neg);
          return "";
        });
        let terms = split(needle);
        let negsRe;
        if (negs.length > 0) {
          negsRe = new RegExp(negs.join("|"), "i" + uFlag);
          if (terms.length == 0) {
            let idxs = [];
            for (let i = 0; i < haystack.length; i++) {
              if (!negsRe.test(haystack[i]))
                idxs.push(i);
            }
            return [idxs, null, null];
          }
        } else {
          if (terms.length == 0)
            return [null, null, null];
        }
        if (outOfOrder > 0) {
          let terms2 = split(needle);
          if (terms2.length > 1) {
            let terms22 = terms2.slice().sort((a, b) => b.length - a.length);
            for (let ti = 0; ti < terms22.length; ti++) {
              if (preFiltered?.length == 0)
                return [[], null, null];
              preFiltered = filter(haystack, terms22[ti], preFiltered);
            }
            if (terms2.length > outOfOrder)
              return [preFiltered, null, null];
            needles = permute(terms2).map((perm) => perm.join(" "));
            matches = [];
            let matchedIdxs = /* @__PURE__ */ new Set();
            for (let ni = 0; ni < needles.length; ni++) {
              if (matchedIdxs.size < preFiltered.length) {
                let preFiltered2 = preFiltered.filter((idx) => !matchedIdxs.has(idx));
                let matched = filter(haystack, needles[ni], preFiltered2);
                for (let j = 0; j < matched.length; j++)
                  matchedIdxs.add(matched[j]);
                matches.push(matched);
              } else
                matches.push([]);
            }
          }
        }
        if (needles == null) {
          needles = [needle];
          matches = [preFiltered?.length > 0 ? preFiltered : filter(haystack, needle)];
        }
        let retInfo = null;
        let retOrder = null;
        if (negs.length > 0)
          matches = matches.map((idxs) => idxs.filter((idx) => !negsRe.test(haystack[idx])));
        let matchCount = matches.reduce((acc, idxs) => acc + idxs.length, 0);
        if (matchCount <= infoThresh) {
          retInfo = {};
          retOrder = [];
          for (let ni = 0; ni < matches.length; ni++) {
            let idxs = matches[ni];
            if (idxs == null || idxs.length == 0)
              continue;
            let needle2 = needles[ni];
            let _info = info(idxs, haystack, needle2);
            let order = opts.sort(_info, haystack, needle2);
            if (ni > 0) {
              for (let i = 0; i < order.length; i++)
                order[i] += retOrder.length;
            }
            for (let k in _info)
              retInfo[k] = (retInfo[k] ?? []).concat(_info[k]);
            retOrder = retOrder.concat(order);
          }
        }
        return [
          [].concat(...matches),
          retInfo,
          retOrder
        ];
      };
      return {
        search: (...args) => {
          let out = _search(...args);
          return out;
        },
        split,
        filter,
        info,
        sort: opts.sort
      };
    }
    var latinize = (() => {
      let accents = {
        A: "\xC1\xC0\xC3\xC2\xC4\u0104",
        a: "\xE1\xE0\xE3\xE2\xE4\u0105",
        E: "\xC9\xC8\xCA\xCB\u0116",
        e: "\xE9\xE8\xEA\xEB\u0119",
        I: "\xCD\xCC\xCE\xCF\u012E",
        i: "\xED\xEC\xEE\xEF\u012F",
        O: "\xD3\xD2\xD4\xD5\xD6",
        o: "\xF3\xF2\xF4\xF5\xF6",
        U: "\xDA\xD9\xDB\xDC\u016A\u0172",
        u: "\xFA\xF9\xFB\xFC\u016B\u0173",
        C: "\xC7\u010C\u0106",
        c: "\xE7\u010D\u0107",
        L: "\u0141",
        l: "\u0142",
        N: "\xD1\u0143",
        n: "\xF1\u0144",
        S: "\u0160\u015A",
        s: "\u0161\u015B",
        Z: "\u017B\u0179",
        z: "\u017C\u017A"
      };
      let accentsMap = /* @__PURE__ */ new Map();
      let accentsTpl = "";
      for (let r in accents) {
        accents[r].split("").forEach((a) => {
          accentsTpl += a;
          accentsMap.set(a, r);
        });
      }
      let accentsRe = new RegExp(`[${accentsTpl}]`, "g");
      let replacer = (m) => accentsMap.get(m);
      return (strings) => {
        if (typeof strings == "string")
          return strings.replace(accentsRe, replacer);
        let out = Array(strings.length);
        for (let i = 0; i < strings.length; i++)
          out[i] = strings[i].replace(accentsRe, replacer);
        return out;
      };
    })();
    function permute(arr) {
      arr = arr.slice();
      let length = arr.length, result = [arr.slice()], c = new Array(length).fill(0), i = 1, k, p;
      while (i < length) {
        if (c[i] < i) {
          k = i % 2 && c[i];
          p = arr[i];
          arr[i] = arr[k];
          arr[k] = p;
          ++c[i];
          i = 1;
          result.push(arr.slice());
        } else {
          c[i] = 0;
          ++i;
        }
      }
      return result;
    }
    var _mark = (part, matched) => matched ? `<mark>${part}</mark>` : part;
    var _append = (acc, part) => acc + part;
    function highlight(str, ranges, mark = _mark, accum = "", append = _append) {
      accum = append(accum, mark(str.substring(0, ranges[0]), false)) ?? accum;
      for (let i = 0; i < ranges.length; i += 2) {
        let fr = ranges[i];
        let to = ranges[i + 1];
        accum = append(accum, mark(str.substring(fr, to), true)) ?? accum;
        if (i < ranges.length - 3)
          accum = append(accum, mark(str.substring(ranges[i + 1], ranges[i + 2]), false)) ?? accum;
      }
      accum = append(accum, mark(str.substring(ranges[ranges.length - 1]), false)) ?? accum;
      return accum;
    }
    uFuzzy.latinize = latinize;
    uFuzzy.permute = (arr) => {
      let idxs = permute([...Array(arr.length).keys()]).sort((a, b) => {
        for (let i = 0; i < a.length; i++) {
          if (a[i] != b[i])
            return a[i] - b[i];
        }
        return 0;
      });
      return idxs.map((pi) => pi.map((i) => arr[i]));
    };
    uFuzzy.highlight = highlight;
    async function init() {
      const defaultContextLen = 100;
      const response = fetch(index_url);
      const search_btn = document.getElementById("search_btn");
      const search_menu_wrapper = document.getElementById("search_menu_wrapper");
      const search_menu_close_btn = document.getElementById("search_menu_close_btn");
      const search_menu_input = document.getElementById("search_menu_input");
      const search_menu_results = document.getElementById("search_menu_results");
      search_btn.addEventListener("click", function() {
        search_menu_wrapper.classList.remove("hidden");
        search_menu_input.focus();
      });
      search_menu_close_btn.addEventListener("click", function() {
        search_menu_wrapper.classList.add("hidden");
      });
      const data = await (await response).json();
      const opts = {
        unicode: true,
        interSplit: "[^\\p{L}\\d']+",
        intraSplit: "\\p{Ll}\\p{Lu}",
        intraBound: "\\p{L}\\d|\\d\\p{L}|\\p{Ll}\\p{Lu}",
        intraChars: "[\\p{L}\\d']",
        intraContr: "'\\p{L}{1,2}\\b"
      };
      const uf = new uFuzzy(opts);
      const haystack = [];
      data.forEach((d) => {
        haystack.push(d["title"], d["content"]);
      });
      const createItem = (title, permalink, content) => {
        return `<a href="${permalink}">
                    <div class="search-menu-result-item">
                        <div class="search-menu-result-item-title">${title}</div>
                        <div class="search-menu-result-item-content">${content}</div>
                    </div>
                </a>`;
      };
      const buildAllItems = () => {
        search_menu_results.innerHTML = data.reduce((acc, curr) => {
          let content = curr.content.length > defaultContextLen ? curr.content.substring(0, defaultContextLen) + "..." : curr.content;
          return acc + createItem(curr.title, curr.permalink, content);
        }, "");
      };
      const mark = (part) => "<mark>" + part + "</mark>";
      const markMatched = (haystackIdx, ranges) => {
        let marktedText = "";
        const text = haystack[haystackIdx];
        let prevTo = 0;
        for (let i = 0; i < ranges.length; i += 2) {
          let fr = ranges[i];
          let to = ranges[i + 1];
          marktedText = marktedText + text.substring(prevTo, fr) + mark(text.substring(fr, to));
          prevTo = to;
        }
        marktedText = marktedText + text.substring(prevTo, text.length);
        return marktedText;
      };
      const markMatchTruncate = (haystackIdx, ranges) => {
        let markedText = "";
        const text = haystack[haystackIdx];
        const prefixContextLen = 20;
        const suffixContextLen = 100;
        let prevCtxTo = -1, prevTo = -1;
        for (let i = 0; i < ranges.length; i += 2) {
          let ctxFr = Math.max(ranges[i] - prefixContextLen, 0);
          let ctxTo = Math.min(ranges[i + 1] + suffixContextLen, text.length);
          let fr = ranges[i];
          let to = ranges[i + 1];
          if (ctxFr <= prevCtxTo) {
            markedText = markedText + text.substring(prevTo, fr);
          } else {
            if (ctxFr !== 0) {
              markedText = markedText + "...";
            }
            markedText = markedText + text.substring(ctxFr, fr);
          }
          markedText = markedText + mark(text.substring(fr, to));
          prevCtxTo = ctxTo;
          prevTo = to;
        }
        markedText = markedText + text.substring(prevTo, prevCtxTo);
        if (prevCtxTo < text.length) {
          markedText = markedText + "...";
        }
        return markedText;
      };
      const search = (value) => {
        const [_, info, order] = uf.search(haystack, value);
        const orderedMatches = [];
        const matchesMap = /* @__PURE__ */ new Map();
        if (order !== null) {
          for (let i = 0; i < order.length; i++) {
            const infoIdx = order[i];
            const haystackIdx = info.idx[infoIdx];
            const dataIdx = Math.floor(haystackIdx / 2);
            const dataType = haystackIdx % 2;
            if (!matchesMap.has(dataIdx)) {
              matchesMap.set(dataIdx, orderedMatches.length);
              const clonedData = { ...data[dataIdx] };
              if (clonedData["content"].length > defaultContextLen) {
                clonedData["content"] = clonedData["content"].substring(0, defaultContextLen) + "...";
              }
              orderedMatches.push(clonedData);
            }
            const match = orderedMatches[matchesMap.get(dataIdx)];
            if (dataType === 0) {
              match["title"] = markMatched(haystackIdx, info.ranges[infoIdx]);
            } else if (dataType === 1) {
              match["content"] = markMatchTruncate(haystackIdx, info.ranges[infoIdx]);
            }
          }
        }
        if (orderedMatches.length == 0) {
          search_menu_results.innerHTML = "";
        } else {
          search_menu_results.innerHTML = orderedMatches.reduce((acc, curr) => {
            return acc + createItem(curr.title, curr.permalink, curr.content);
          }, "");
        }
      };
      search_menu_input.addEventListener("input", function() {
        if (this.value === "") {
          buildAllItems();
        } else {
          search(this.value.trim());
        }
      });
      buildAllItems();
    }
    window.addEventListener("DOMContentLoaded", init);
  })();
})();
