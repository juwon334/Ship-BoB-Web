/* Copyright (c) 2015-2019, Chandan B.N.
 *
 * Copyright (c) 2019, FIRST.ORG, INC
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*

CVSSjs Version 0.1 beta

Usage:
    craete an html element with an id for eg.,
    <div id="cvssboard"></div>

    // create a new instance of CVSS calculator:
    var c = new CVSS("cvssboard");

    // create a new instance of CVSS calculator with some event handler callbacks
    var c = new CVSS("cvssboard", {
                onchange: function() {....} //optional
                onsubmit: function() {....} //optional
                }
                
    // set a vector
    c.set('AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L');
    
    //get the value
    c.get() returns an object like:

    {
        score: 4.3,
        vector: 'AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L'
    }
    
*/

var CVSS = function (id, options) {
    this.options = options;
    this.wId = id;
    var e = function (tag) {
        return document.createElement(tag);
    };

    // Base Group
    this.bg = {
        CAT: '시스템 카테고리(CAT)',
        P: '영향(P)',
        CX: '복잡성(CX)',
        CY: '연결성(CY)',
        US: '사용자 수준(US)',
        AT: '공격자 수준(AT)',
    };

    // Base Metrics
    this.bm = {
        CAT: {
            A:{
                l: 'CAT III',
                d: '<b>Worst:</b>고장이 즉시 사람, 선박의 안전에 대한 위협으로 이어짐.(환경 재해 포함)<ul><li>선박 추진 시스템 (기계적 추력을 생성하고 제어하는 수단) (선수 터널 추진기와 같이 기동 중에만 사용되면 포함 x)</li><li>전력 시스템 (전력 관리 시스템 포함)</li><li>선박 안전 시스템 (화재 감지 및 진화, 침수 감지 및 진화, 대피 단계 관련 내부 통신, 구명 기구 장비 작동)</li><li>IMO MSC/Circ. 645에 따른 장비 등급 2및 3의 동적 위치 시스템</li></ul>'

            },
            B: {
                l: 'CAT II',
                d: '<b>Bad:</b> 고장이 사람, 선박의 안전에 위험한 상황을 초래함. (환경 재해 포함)<ul><li>액체 화물 운송 제어 시스템</li><li>bilge 레벨 감지(선박 높이 감지)및 관련 펌프 제어</li><li>연료유 처리 시스템</li><li>밸러스트 이송 밸브 원격 시스템</li><li>안정화 및 승차감 제어 시스템</li><li>추진 시스템용 경보 및 모니터링 시스템</li></ul>'
            },
            C: {
                l: 'CAT I',
                d: '<b>Good:</b> 고장이 사람, 선박의 안전 위협으로 이어지지 않음. (환경 재해 포함)'
            }
        },
        P: {
            A: {
                l: 'P5',
                d: '<b>Catastrophic:</b> 다음 중 하나 이상의 영향을 미치는 이벤트<ul><li>물리적 시스템 파괴 (e.g. 화재, 폭발)</li><li>선박의 분실 (e.g. 충돌 또는 접안)</li><li>차량이 오프라인 상태가 됨 (e.g. 시스템 정전, 법적 조사)</li><li>장기적인 환경적 영향을 미치는 환경 재해(e.g. 주요 오염)</li><li>재정적 손실이 선주 파산으로 이어짐</li><li>인명 피해로 다수의 사망자, 승무원, 승객의 납치</li></ul>'
            },
            B: {
                l: 'P4',
                d: '<b>High:</b> 다응 중 하나 이상의 영향을 미치는 이벤트<ul><li>물리적 시스템 손상 (재료 파손 등)</li><li>표준 복원 프로세스 없이 시스템을 작동 상태로 재시작할 수 없는 영구적인 시스템 손실 (e.g. 랜섬웨어)</li><li>선박이 꺼짐 (e.g. 화물 관리 시스템의 종료)</li><li>규제 당국이 조사를 요청하는 경우</li><li>불법 인신매매</li><li>심각한 오염으로 인해 사람들이 대피하는 경우</li><li>장기적인 경쟁력 상실</li><li>사람에 대한 충격이 죽음으로 이어진 경우</li></ul>'
            },
            C: {
                l: 'P3',
                d: '<b>Moderate:</b>다음 중 하나 이상의 영향을 미치는 이벤트<ul><li>시스템 활동 손실이 심각함 (e.g. 메일 시스템이 꺼져있고, IT 부서가 복구하는데 시간이 소요됨)</li><li>선주가 제 3자 위원회에 조사를 요청하는 경우 (e.g. 설명할 수 없는 비즈니스 활동 중단, 부인 방지 기능 손실)</li><li>기밀 정보 손실 (e.g. 데이터 유출, 경쟁사 노하우 공개)</li><li>선주가 용납할 수 없는 것으로 간주되는 재정적 손실</li><li>사기 및 금전 도난</li><li>훼손된 평판</li><li>제한적인 환경에 미치는 영향</li><li>인간의 영구적 장애</li></ul>'
            },
            D: {
                l: 'P2',
                d: '<b>Acceptable:</b>다음 중 하나 이상의 영향을 미치는 이벤트<ul><li>시스템 종료 → 서비스 중단</li><li>환경적 영향 → 당국에 신고될 수 있음</li><li>부상 및 의학적 치료 → 노동의 중단</li></ul>'
            },
            E: {
                l: 'P1',
                d: '<b>Negligible:</b><ul><li>시스템이 별 다른 영향 없이 종료될 수 있음.</li><li>인간이나 환경에 영향을 미치지 않음.</li></ul>'
            }
        },
        CX: {
            A: {
                l: 'CX3',
                d: '<b>Distributed Systems:</b> - 원격 또는 분산 아키텍처를 통해 장비를 분산시켜 운영성과 효율성을 높여야 하는 시스템을 말함. → 무인 선박, 스웜 로봇, 분산 시스템 아키텍처'
            },
            B: {
                l: 'CX2',
                d: '<b>Living Systems:</b> 소프트웨어, 구성 파일 또는 운영 체제가 매일 수정되거나 업데이트 되는 시스템 또는 장비임. (e.g. 식별 및 인증서버, DBMS, 네트워크 장비, 가상 머신 모니터, 계산기, 선박 운영에 직접적인 영향을 미치는 결정을 내리는데 사용되는 스마트 장비)'
            },
            C: {
                l: 'CX1',
                d: '<b>Low-maintenance Systems:</b> 작동하는데 구성 변경이 거의 또는 전혀 필요하지 않은 모든 시스템(모든 업데이트 및 수정 유지 보수 제외) (e.g. 워크 스테이션)'
            }
        },
        CY: {
            A: {
                l: 'CY5',
                d: '<b>Open Connectivity Systems:</b> 공용 네트워크 액세스에 대한 외부 링크가 있거나 특수 보호에 대한 지식이 없는 모든 시스템.'
            },
            B: {
                l: 'CY4',
                d: '<b>DMZ:</b> 선박 외부에 링크가 있는 모든 시스템(e.g. 게이트웨이, 원격 관리 링크, 웹 서비스 등)<br>인터넷 연결에 대해 DMZ 유형 아키텍처가 배포되는 기존 VPN(VPN PPTT, SSL, TLS) 같은 인증된 네트워크를 구현함.'
            },
            C: {
                l: 'CY3',
                d: '<b>Network System:</b> 선박 내부에 하나 이상의 이더넷, 광, 와이파이 상호 연결 또는 검증된 관리, 인증된 프로토콜을 사용하는 외부 연결을 공유하는 모든 시스템.'
            },
            D: {
                l: 'CY2',
                d: '<b>Closed connectivity System:</b> 데이터 교환을 위해서만 하나 이상의 상호 연결을 공유하는 모든 시스템. 다음과 같은 프로토콜을 사용하여 폐쇄된 환경의 선박 내에서 이루어짐 → NMEA, Modbus, dry contact, Serial'
            },
            E: {
                l: 'CY1',
                d: '<b>Isolated System:</b> 기내 또는 육상의 다른 시스템과 연결되지 않은 모든 시스템'
            }
        },
        US: {
            A: {
                l: 'US4',
                d: '<b>Any User:</b><ul><li>사이버 보안 교육 또는 인식과 관련된 바가 없음</li><li>물리적 액세스 보호 없음</li><li>논리적 액세스 보호 없음</li></ul>'
            },
            B: {
                l: 'US3',
                d: '<b>Accredited User:</b><ul><li>사이버 보안에 대한 교육과 인식이 매우 부족함</li><li>회사 또는 마스터의 인증을 통해 물리적 액세스가 허용됨</li><li>논리적 액세스 보호는 존재하지 않음.</li></ul>'
            },
            C: {
                l: 'US2',
                d: '<b>Controlled User:</b><ul><li>사이버 보안에 대해 알고 있지만 조치 실행에 대한 교육은 제대로 받지 못함.</li><li>방은 물리적으로 잠겨있으며, 출입은 회사 또는 마스터로부터 인증됨.</li><li>일반 액세스 권한과 일반 비밀번호를 가짐.</li></ul>'
            },
            D: {
                l: 'US1',
                d: '<b>Aware User:</b><ul><li>사이버 보안 조치를 구현하는 방법을 잘 알고 있음.</li><li>방은 물리적으로 잠겨있으며, 출입은 회사 또는 마스터로부터 인증됨.</li><li>사용자 전용 계정과 비공개 비밀번호가 있음.</li></ul>'
            }
        },
        AT: {
            A: {
                l: 'AT5',
                d: '<b>Cyber warfare Attacker:</b> 공격자는 국가 지원 공격 사용함. 이 등급은 해군 함정에만 적용됨.'
            },
            B: {
                l: 'AT4',
                d: '<b>Criminal Attacker:</b> 해운 회사, 선단 및 선박에 대한 정보를 수집하기 위해 시간과 비용을 기꺼이 투자함. 지능형 지속 위협(APT)를 설치하기 위해 시스템에 침투하기 위한 전용 시나리오를 구축함.'
            },
            C: {
                l: 'AT3',
                d: '<b>Standard Attacker:</b> 해킹 도구 및 기술을 사용하는 악의적인 의도를 가진 모든 공격자(내부, 외부). 기본적으로 적용될 수 있음.'
            },
            D: {
                l: 'AT2',
                d: '<b>Insider Attacker:</b> 악의적인 의도 없이 시스템 보안을 우회하려는 승무원(e.g. 장비 튜닝, 땜장이, 윤리적 해커)로 한정하여 정의'
            },
            E: {
                l: 'AT1',
                d: '<b>Unintentional Attacker:</b> 승무원이 의도치 않게 기내에 타겟이 아닌 일반적인 바이러스 또는 멀웨어를 설치한 경우'
            }
        }



    };
    // US, AS 필요. 
    
    this.bme = {};
    this.bmgReg = {
        CAT: 'ABC',
        P: 'ABCDE',
        CX: 'ABC',
        CY: 'ABCDE',
        US: 'ABCD',
        AT: 'ABCDE'
    };
    this.bmoReg = {
        CAT: 'ABC',
        P: 'ABCDE',
        CX: 'ABC',
        CY: 'ABCDE',
        US: 'ABCD',
        AT: 'ABCDE'
    };
    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            //inp.setAttribute('ontouchstart', '');
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function () {
                me.setMetric(this);
            };
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    //f.appendChild(e('hr'));
    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>Risk Level(RL)</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    l.appendChild(this.score = e('span'));
    this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'IACS:171/CAT:_/P:_/CX:_/CY:_';
    
    if (options.onsubmit) {
        f.appendChild(e('hr'));
        this.submitButton = f.appendChild(e('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
};

CVSS.prototype.severityRatings = [{
    name: "Optional",
    bottom: -100.0,
    top: -0.1
}, {
    name: "None",
    bottom: 0.0,
    top: 0.9
}, {
    name: "Optional",
    bottom: 1.0,
    top: 3.9
}, {
    name: "Appropriate",
    bottom: 4.0,
    top: 12.0
}, {
    name: "Required",
    bottom: 12.1,
    top: 100.0
}];

CVSS.prototype.severityRating = function (score) {
    var i;
    var severityRatingLength = this.severityRatings.length;
    for (i = 0; i < severityRatingLength; i++) {
        if (score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top) {
            return this.severityRatings[i];
        }
    }
    return {
        name: "?",
        bottom: 'Not',
        top: 'defined'
    };
};

CVSS.prototype.valueofradio = function(e) {
    for(var i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
};

CVSS.prototype.calculate = function () {
    var Weight = {
        CAT: {
            A: 3,
            B: 2,
            C: 1
        },
        P: {
            A: 5,
            B: 4,
            C: 3,
            D: 2,
            E: 1
        },
        CX: {
            A: 2,
            B: 1,
            C: 0
        },
        CY: {
            A: 4,
            B: 3,
            C: 2,
            D: 1,
            E: 0
        },
        US: {
            A: 3,
            B: 2,
            C: 1,
            D: 0
        },
        AT: {
            A: 4,
            B: 3,
            C: 2,
            D: 1,
            E: 0
        }
    };

    var p;
    var val = {}, metricWeight = {};
    try {
        for (p in this.bg)
        {
            val[p] = this.valueofradio(this.calc.elements[p]);
            if (typeof val[p] == "undefined" || val[p] === null)
            {
                return "?";
            }
            metricWeight[p] = Weight[p][val[p]];
        }
    } catch (err) {
        return err;
    }
    var AS = 0, H = 0;
    let ASMatrix = [
        [0, 1, 2, 3, 4],
        [1, 1, 2, 3, 4],
        [2, 2, 3, 3, 4]
    ];
    let HMatrix = [
        [0, 1, 1, 2],
        [1, 1, 2, 2],
        [1, 2, 2, 3],
        [2, 2, 3, 3],
        [2, 3, 3, 4]
    ];

    AS = ASMatrix[metricWeight.CX][metricWeight.CY];
    H = HMatrix[metricWeight.AT][metricWeight.US];

    var L = 0;
    let LMatrix = [
        [1, 2, 3, 4, 5],
        [2, 3, 4, 5, 6],
        [3, 4, 5, 6, 7],
        [4, 5, 6, 7, 8],
        [5, 6, 7, 8, 9]
    ];
    L = LMatrix[AS][H];

    var RL;
    RL = 2 * (metricWeight.CAT + metricWeight.P + L - 4);

    return RL.toFixed(1);
};

CVSS.prototype.get = function() {
    return {
        score: this.score.innerHTML,
        vector: this.vector.innerHTML
    };
};

CVSS.prototype.setMetric = function(a) {
    var vectorString = this.vector.innerHTML;
    if (/CAT:.\/P:.\/CX:.\/CY:./.test(vectorString)) {} else {

        vectorString = 'CAT:_/P:_/CX:_/CY:_';
    }
    //e("E" + a.id).checked = true;
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
};

CVSS.prototype.set = function(vec) {
    var newVec = 'IACS171/';
    var sep = '';
    for (var m in this.bm) {
        var match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec);
        if (match !== null) {
            var check = match[0].replace(':', '');
            this.bme[check].checked = true;
            newVec = newVec + sep + match[0];
        } else if ((m in {C:'', I:'', A:''}) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
            // compatibility with v2 only for CIA:C
            this.bme[m + 'H'].checked = true;
            newVec = newVec + sep + m + ':H';
        } else {
            newVec = newVec + sep + m + ':_';
            for (var j in this.bm[m]) {
                this.bme[m + j].checked = false;
            }
        }
        sep = '/';
    }
    this.update(newVec);
};

CVSS.prototype.update = function(newVec) {
    this.vector.innerHTML = newVec;
    var s = this.calculate();
    this.score.innerHTML = s;
    var rating = this.severityRating(s);
    this.severity.className = rating.name + ' severity';
    this.severity.innerHTML = rating.name + '<sub>' + rating.bottom + ' - ' + rating.top + '</sub>';
    this.severity.title = rating.bottom + ' - ' + rating.top;
    if (this.options !== undefined && this.options.onchange !== undefined) {
        this.options.onchange();
    }
};