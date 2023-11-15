// work in progress

vectorMap4 = {
    "attackVector": "AV",
    "attackComplexity": "AC",
    "attackRequirements": "AT",
    "privilegesRequired": "PR",
    "userInteraction": "UI",
    "vulnConfidentialityImpact": "VC",
    "vulnIntegrityImpact": "VI",
    "vulnAvailabilityImpact": "VA",
    "subConfidentialityImpact": "SC",
    "subIntegrityImpact": "SI",
    "subAvailabilityImpact": "SA",
    "Safety": "S",
    "Automatable": "AU",
    "Recovery": "R",
    "valueDensity": "V",
    "vulnerabilityResponseEffort": "RE",
    "providerUrgency": "U",
    "exploitMaturity": "E"
};

function invertObject(obj) {
	const inverted = {};
	for (const key in obj) {
	  inverted[obj[key]] = key;
	}
	return inverted;
}
 

var metricMap4 = invertObject(vectorMap4);

var valueMap = {
	"UNDEFINED": "X",
    "GREEN": "Green",
    "RED": "Red",
    "CLEAR": "Clear",
    "AMBER": "Amber"
};

function vector(cv){
	var v = "CVSS:4.0";
	for(const key in metricMap4) {
		if(cv[key])
			v = v + '/' + key + ':' + cv[key]
	}
	return v;
}

function vectorize(c) {
	var cv = {};
	for(const key in c){
		var m = vectorMap4[key];
		var v = undefined;
		console.log(key +'='+ c[key])
		if(m && c[key]) {
			v = valueMap[c[key]] || c[key].charAt(0);
		}
		if(v) {
			cv[m]=v;
		}
	}
	return cv;
}

function vectorizeString(s) {
	var cv = {};
	var metrics = s.split("/");
	for(index in metrics) {
		var [key, value] = metrics[index].split(":");
		cv[key] = value;
	}
	return cv;
}

function macroVector(cvss) {
	var c = vectorize(cvss);

    var N='N', P='P', X='X', H='H', L='L', R='R', S = 'S';

    var av = c.AV,
        ac = c.AC,
        ui = c.UI,
        at = c.AT,
        pr = c.PR,
        vc = c.VC,
        va = c.VA,
        vi = c.VI,
        sc = c.SC,
        si = c.SI,
        sa = c.SA,
        e = e,
        cr = c.CR,
        ir = c.IR,
        ar = c.AR,
		msi = c.MSI,
		msa = c.MSA
		;

	if([vc, vi, va, sc, si, sa].every((met) => met == N)) {
		return 0;
	}


	// Compute EQs
	// => EQ1 - Table 25
	var eq = [];
	eq[1] = 0;
	if(av == N && pr == N && ui == N) {
		eq[1] = 0
	} else if ((av == N || pr == N || ui == N) && !(av == N && pr == N && ui == N) && !(av == P)) {
		eq[1] = 1
	} else if (av == P || !(av == N || pr == N || ui == N)) {
		eq[1] = 2
	} else {
		console.log("EQ1 invalid CVSS configuration: AV:%s/PR:%s/UI:%s\n", av, pr, ui);
		return undefined;
	}
	// => EQ2 - Table 26
	eq[2] = 0
	if (ac == L && at == N) {
		eq[2] = 0
	} else if (!(ac == L && at == N)) {
		eq[2] = 1
	} else {
		console.log("EQ2 invalid CVSS configuration: AC:%s/AT:%s\n", ac, at)
		return undefined;
	}
	// => EQ3 - Table 27
	eq[3] = 0;
	if(vc == H && vi == H){
		eq[3] = 0
	} else if (!(vc == H && vi == H) && (vc == H || vi == H || va == H)) {
		eq[3] = 1
	} else if (!(vc == H || vi == H || va == H)) {
		eq[3] = 2
	} else {
		console.log("EQ3 invalid CVSS configuration: VC:%s/VI:%s/VA:%s\n", vc, vi, va)
		return undefined;

	}
	// => EQ4 - Table 28
	eq[4] = 0
	if (msi == S || msa == S) {
		eq[4] = 0
	} else if (!(msi == S && msa == S) && (sc == H || si == H || sa == H)) {
		eq[4] = 1
	} else if (!(msi == S && msa == S) && !(sc == H || si == H || sa == H)) {
		eq[4] = 2
	} else {
		console.log("EQ4 invalid CVSS configuration: MSI:%s/MSA:%s/SC:%s/SI:%s/SA:%s\n", msi, msa, cvss40.get("SC"), cvss40.get("SI"), cvss40.get("SA"))
		return undefined;
	}
	// => EQ5 - Table 29
	eq[5] = 0
	if (e == "A" || e == X || e == undefined) {
		eq[5] = 0
	} else if (e == "P") {
		eq[5] = 1
	} else if (e == "U") {
		eq[5] = 2
	} else {
		console.log("EQ5 invalid CVSS configuration: E:%s\n", e)
		return undefined;
	}
	// => EQ6 - Table 30
	eq[6] = 0
	if (av == N && pr == N && ui == N) {
		eq[6] = 0
	} else if ((cr == H && vc == H) || (c.IR == H && vi == H) || (c.AR == H && va == H) ){
		eq[6] = 1
	} else {
		console.log("EQ6 invalid CVSS configuration: AV:%s/PR:%s/UI:%s/CR:%s/VC:%s/IR:%s/VI:%s/AR:%s/VA:%s\n", av, pr, ui, cr, vc, c.IR, vi)
		return undefined;

	}
	// => EQ3+EQ6 - Table 31
	eq[7]= 0
	if (vc == H && vi == H && (cr == H || ir == H || (ar == H && va == H))) {
		eq[7] = '00';
	} else if (vc == H && vi == H && !(cr == H || ir == H) && !(ar == H && va == H)) {
		eq[7] = '01';
	} else if (!(vc == H && vi == H) && (vc == H || vi == H || va == H) && (cr == H && vc == H) || (ir == H && vi == H) || (ar == H && va == H)) {
		eq[7] = 10;
	} else if (!(vc == H && vi == H) && (vc == H || vi == H || va == H) && !(cr == H && vc == H) && !(ir == H && vi == H) && !(ar == H && va == H)) {
		eq[7] = 11;
	} else if (!(vc == H || vi == H || va == H) && (cr == H && vc == H) || (ir == H && vi == H) || (ar == H && va == H)){
		eq[7] = 20;
	} else if (!(vc == H || vi == H || va == H) && !(cr == H && vc == H) && !(ir == H && vi == H) && !(ar == H && va == H)) {
		eq[7] = 21;
	} else {
		console.log("EQ36 invalid CVSS configuration: CR:%s/VC:%s/IR:%s/VI:%s/AR:%s/VA:%s\n", cr, vc, ir, vi, ar, va)
		return undefined;
	}
	var current = eq;
	var diff = [];
	var currentScore = lookup(eq);
	for(const eqSet = 1; eqSet < 7; eqSet++) {
		var lowSet =  Array.from(originalArray);
		lowSet[eqSet] = lowSet[eqSet]+1;
		var lowScore = lookup(lowSet);
		var maxDiff = currentScore - lowScore;
		var mV = maxVectors(eqSet);
		var hammingDistance = 0;
		for(const m in mV) {
			var hd = getHammingDistance(c, vectorizeString(m));
			if(hd > hammingDistance) {
				hammingDistance = hd;
			}
		}
		var prop = hammingDistance/depth;
		diff[eqSet] = maxDiff * prop;
	}
}

function getHammingDistance(a, b) {
	var dist = {};
	for(const key in a) {
		dist[key] = levels[key][a[key]] - levels[key][b[key]];
	}
	if(a.MSI == 'S') {
		dist.SI = levels.SI['S'] -  levels.SI[b.SI]
	}
	if(a.MSA == 'S') {
		dist.SI = levels.SA['S'] -  levels.SA[b.SA]
	}
	var ret = 0;
	for(const key in dist) {
		ret = ret + Math.abs(dist[key]);
	}
	return ret;
}

const maxHamming = {
	"eq1" : {
		"0" : 1,
		"1" : 4,
		"2" : 5
	},
	"eq2" : {
		"0" : 1,
		"1" : 2
	},
	"eq3" : {
		"00": 7, 
		"01": 6,
		"10": 8,
		"11": 8,
		"21": 10
	},
	"eq4" : {
		"0" : 6,
		"1" : 5,
		"2" : 4

	},
	"eq5" : {
		"0" : 1,
		"1" : 1,
		"2" : 1
	},
}

function maxVectors(eqSet, eqVal) {
	return maxComposed[eqSet-1][eqVal];
}

const maxComposed = [
	{
		"0": ["AV:N/PR:N/UI:N/"],
		"1" : ["AV:A/PR:N/UI:N/","AV:N/PR:L/UI:N/","AV:N/PR:N/UI:P/"],
		"2": ["AV:P/PR:N/UI:N/","AV:A/PR:L/UI:P/"]
	},
	{
		"0" : ["AC:L/AT:N/"],
		"1" : ["AC:H/AT:N/","AC:L/AT:P/"]
	},
	{
		"00": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
		"01": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/","VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
		"10": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/","VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
		"11": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/","VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/","VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/","VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/","VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"],
		"21": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]
	},
	{
		"0" : ["SC:H/SI:S/SA:S/"],
		"1" : ["SC:H/SI:H/SA:H/"],
		"2" : ["SC:L/SI:L/SA:L/"]

	},
	{
		"0" : ["E:A/"],
		"1" : ["E:P/"],
		"2" : ["E:U/"],
	},
]

function lookup(m) {
	var score = lookuptable[m.join('');
	return score;
}

const lookuptable = {
	"000000": 10,
	"000001": 9.9,
	"000010": 9.8,
	"000011": 9.5,
	"000020": 9.5,
	"000021": 9.2,
	"000100": 10,
	"000101": 9.6,
	"000110": 9.3,
	"000111": 8.7,
	"000120": 9.1,
	"000121": 8.1,
	"000200": 9.3,
	"000201": 9,
	"000210": 8.9,
	"000211": 8,
	"000220": 8.1,
	"000221": 6.8,
	"001000": 9.8,
	"001001": 9.5,
	"001010": 9.5,
	"001011": 9.2,
	"001020": 9,
	"001021": 8.4,
	"001100": 9.3,
	"001101": 9.2,
	"001110": 8.9,
	"001111": 8.1,
	"001120": 8.1,
	"001121": 6.5,
	"001200": 8.8,
	"001201": 8,
	"001210": 7.8,
	"001211": 7,
	"001220": 6.9,
	"001221": 4.8,
	"002001": 9.2,
	"002011": 8.2,
	"002021": 7.2,
	"002101": 7.9,
	"002111": 6.9,
	"002121": 5,
	"002201": 6.9,
	"002211": 5.5,
	"002221": 2.7,
	"010000": 9.9,
	"010001": 9.7,
	"010010": 9.5,
	"010011": 9.2,
	"010020": 9.2,
	"010021": 8.5,
	"010100": 9.5,
	"010101": 9.1,
	"010110": 9,
	"010111": 8.3,
	"010120": 8.4,
	"010121": 7.1,
	"010200": 9.2,
	"010201": 8.1,
	"010210": 8.2,
	"010211": 7.1,
	"010220": 7.2,
	"010221": 5.3,
	"011000": 9.5,
	"011001": 9.3,
	"011010": 9.2,
	"011011": 8.5,
	"011020": 8.5,
	"011021": 7.3,
	"011100": 9.2,
	"011101": 8.2,
	"011110": 8,
	"011111": 7.2,
	"011120": 7,
	"011121": 5.9,
	"011200": 8.4,
	"011201": 7,
	"011210": 7.1,
	"011211": 5.2,
	"011220": 5,
	"011221": 3,
	"012001": 8.6,
	"012011": 7.5,
	"012021": 5.2,
	"012101": 7.1,
	"012111": 5.2,
	"012121": 2.9,
	"012201": 6.3,
	"012211": 2.9,
	"012221": 1.7,
	"100000": 9.8,
	"100001": 9.5,
	"100010": 9.4,
	"100011": 8.7,
	"100020": 9.1,
	"100021": 8.1,
	"100100": 9.4,
	"100101": 8.9,
	"100110": 8.6,
	"100111": 7.4,
	"100120": 7.7,
	"100121": 6.4,
	"100200": 8.7,
	"100201": 7.5,
	"100210": 7.4,
	"100211": 6.3,
	"100220": 6.3,
	"100221": 4.9,
	"101000": 9.4,
	"101001": 8.9,
	"101010": 8.8,
	"101011": 7.7,
	"101020": 7.6,
	"101021": 6.7,
	"101100": 8.6,
	"101101": 7.6,
	"101110": 7.4,
	"101111": 5.8,
	"101120": 5.9,
	"101121": 5,
	"101200": 7.2,
	"101201": 5.7,
	"101210": 5.7,
	"101211": 5.2,
	"101220": 5.2,
	"101221": 2.5,
	"102001": 8.3,
	"102011": 7,
	"102021": 5.4,
	"102101": 6.5,
	"102111": 5.8,
	"102121": 2.6,
	"102201": 5.3,
	"102211": 2.1,
	"102221": 1.3,
	"110000": 9.5,
	"110001": 9,
	"110010": 8.8,
	"110011": 7.6,
	"110020": 7.6,
	"110021": 7,
	"110100": 9,
	"110101": 7.7,
	"110110": 7.5,
	"110111": 6.2,
	"110120": 6.1,
	"110121": 5.3,
	"110200": 7.7,
	"110201": 6.6,
	"110210": 6.8,
	"110211": 5.9,
	"110220": 5.2,
	"110221": 3,
	"111000": 8.9,
	"111001": 7.8,
	"111010": 7.6,
	"111011": 6.7,
	"111020": 6.2,
	"111021": 5.8,
	"111100": 7.4,
	"111101": 5.9,
	"111110": 5.7,
	"111111": 5.7,
	"111120": 4.7,
	"111121": 2.3,
	"111200": 6.1,
	"111201": 5.2,
	"111210": 5.7,
	"111211": 2.9,
	"111220": 2.4,
	"111221": 1.6,
	"112001": 7.1,
	"112011": 5.9,
	"112021": 3,
	"112101": 5.8,
	"112111": 2.6,
	"112121": 1.5,
	"112201": 2.3,
	"112211": 1.3,
	"112221": 0.6,
	"200000": 9.3,
	"200001": 8.7,
	"200010": 8.6,
	"200011": 7.2,
	"200020": 7.5,
	"200021": 5.8,
	"200100": 8.6,
	"200101": 7.4,
	"200110": 7.4,
	"200111": 6.1,
	"200120": 5.6,
	"200121": 3.4,
	"200200": 7,
	"200201": 5.4,
	"200210": 5.2,
	"200211": 4,
	"200220": 4,
	"200221": 2.2,
	"201000": 8.5,
	"201001": 7.5,
	"201010": 7.4,
	"201011": 5.5,
	"201020": 6.2,
	"201021": 5.1,
	"201100": 7.2,
	"201101": 5.7,
	"201110": 5.5,
	"201111": 4.1,
	"201120": 4.6,
	"201121": 1.9,
	"201200": 5.3,
	"201201": 3.6,
	"201210": 3.4,
	"201211": 1.9,
	"201220": 1.9,
	"201221": 0.8,
	"202001": 6.4,
	"202011": 5.1,
	"202021": 2,
	"202101": 4.7,
	"202111": 2.1,
	"202121": 1.1,
	"202201": 2.4,
	"202211": 0.9,
	"202221": 0.4,
	"210000": 8.8,
	"210001": 7.5,
	"210010": 7.3,
	"210011": 5.3,
	"210020": 6,
	"210021": 5,
	"210100": 7.3,
	"210101": 5.5,
	"210110": 5.9,
	"210111": 4,
	"210120": 4.1,
	"210121": 2,
	"210200": 5.4,
	"210201": 4.3,
	"210210": 4.5,
	"210211": 2.2,
	"210220": 2,
	"210221": 1.1,
	"211000": 7.5,
	"211001": 5.5,
	"211010": 5.8,
	"211011": 4.5,
	"211020": 4,
	"211021": 2.1,
	"211100": 6.1,
	"211101": 5.1,
	"211110": 4.8,
	"211111": 1.8,
	"211120": 2,
	"211121": 0.9,
	"211200": 4.6,
	"211201": 1.8,
	"211210": 1.7,
	"211211": 0.7,
	"211220": 0.8,
	"211221": 0.2,
	"212001": 5.3,
	"212011": 2.4,
	"212021": 1.4,
	"212101": 2.4,
	"212111": 1.2,
	"212121": 0.5,
	"212201": 1,
	"212211": 0.3,
	"212221": 0.1
}

function getLevel(m,v) {
	return levels[m][v]
}

const levels = {
	'AV': {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
	'PR': {"N": 0.0, "L": 0.1, "H": 0.2},
	'UI': {"N": 0.0, "P": 0.1, "A": 0.2},
	'AC': {'L':0.0, 'H':0.1},
	'AT': {'N':0.0, 'P':0.1},
	'VC': {'H':0.0, 'L':0.1, 'N':0.2},
	'VI': {'H':0.0, 'L':0.1, 'N':0.2},
	'VA': {'H':0.0, 'L':0.1, 'N':0.2},
	'SC': {'H':0.1, 'L':0.2, 'N':0.3},
	'SI': {'S':0.0, 'H':0.1, 'L':0.2, 'N':0.3},
	'SA': {'S':0.0, 'H':0.1, 'L':0.2, 'N':0.3},
	'CR': {'H':0.0, 'M':0.1, 'L':0.2},
	'IR': {'H':0.0, 'M':0.1, 'L':0.2},
	'AR': {'H':0.0, 'M':0.1, 'L':0.2},
	'E': {'U': 0.2, 'P': 0.1, 'A': 0}
}

function score(mv) {
	var eq1 = mv[0],
	eq2 = mv[1],
	eq3 = mv[2],
	eq4 = mv[3],
	eq5 = mv[4],
	eq6 = mv[5],
	eq36 = mv[6];
}
