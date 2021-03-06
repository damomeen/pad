from pyparsing import Literal, Keyword, Word, Group, Combine, Dict
from pyparsing import OneOrMore, ZeroOrMore, Optional, nums, alphas
import unittest

# ------------- COMMON LITERALS and WORDS --------------------------------------------------------------------------

LBRACK = Literal("{").suppress()
RBRACK = Literal("}").suppress()
LPARENTHES = Literal("(").suppress()
RPARENTHES = Literal(")").suppress()
EQUALS = Literal(":").suppress()
SEMI   = Literal(";").suppress()
COMMA   = Literal(",").suppress()

FIELD = Word(alphas + '_')
FIELD_LEN = Word(nums)
PROTOCOL = Word(alphas + '_' + nums)
VALUE = Word(nums)
ACTION = Word(alphas + '_' + nums)

# ------------- UTILITY FUNCTIONS -------------------------------------------------------------------------------------
    
def fields2dict(s, l, t):
    d = {'fields':[]}
    for field in t[0][1:]:
        field, len = field
        d['fields'].append({'field':field, 'length': len})
    return d
    
def header2dict(s, l, t):
    d = dict()
    d['header'] = t[0][1]
    d.update(t[0][2])
    return d
    
def start2dict(s, l, t):
    return {t[0][1]: t[0][2]}
    
def parser2dict(s, l, t):
    return start2dict(s, l, t)

def case2dict(s, l, t):
    return {t[0][2]: t[0][1]}
    
def switch2dict(s, l, t):
    cases = dict()
    for v in t[0][2:]:
        cases.update(v)
    return [t[0][1], cases]
    
def sizeof2dict(s, l, t):
    return {t[0][0]: t[0][1]}
    
def addheader2dict(s, l, t):
    return {"function": t[0][0], "header":t[0][1], "offset":t[0][2]}
    
def remheader2dict(s, l, t):
    return addheader2dict(s, l, t)
    
def instruction2list(s, l, t):
    return t[0]
    
# ------------- PYPARSE DEFINICTIONS  ------------------------------------------------------------------------------

def p4_header():
    field_info = Group(FIELD + EQUALS + FIELD_LEN + SEMI)
    fields = Group(Keyword("fields") + LBRACK + OneOrMore(field_info) + RBRACK).setParseAction(fields2dict)
    return Group(Keyword("header") + PROTOCOL +  LBRACK + fields + RBRACK).setParseAction(header2dict)
    
def p4_parser():
    field_value = Combine(Optional("0x") + VALUE)
    case = Group(Keyword("case") + field_value + EQUALS + PROTOCOL + SEMI).setParseAction(case2dict)
    cases = OneOrMore(case)
    switch = Group(Keyword("switch") + LPARENTHES + FIELD + RPARENTHES + LBRACK + cases + RBRACK).setParseAction(switch2dict)
    parser = Group(Keyword("parser") + PROTOCOL + LBRACK + switch + RBRACK)
    starter = Group(Keyword("parser") + Keyword("start") + LBRACK + PROTOCOL + SEMI + RBRACK)
    return starter, parser
    
def p4_action():
    sizeof = Group(Keyword("sizeof") + LPARENTHES + PROTOCOL + RPARENTHES).setParseAction(sizeof2dict)
    offset = sizeof                 # other possibilities to be addded later
    add_header_func = Group(Keyword("add_header") + LPARENTHES + PROTOCOL + COMMA + offset + RPARENTHES + SEMI).setParseAction(addheader2dict)
    rem_header_func = Group(Keyword("remove_header") + LPARENTHES + PROTOCOL + COMMA + offset + RPARENTHES + SEMI).setParseAction(remheader2dict)
    basic_instruction = Group(add_header_func | rem_header_func).setParseAction(instruction2list)
    basic_instructions = OneOrMore(basic_instruction)
    return Group(Keyword("action") + ACTION + LBRACK + basic_instructions + RBRACK)

# ------------- PARSE FUNCTIONS  -------------------------------------------------------------------------------------

def parse_p4(spec):
    p4header = p4_header()
    p4parser, p4starter = p4_parser()
    p4action = p4_action()
    p4 = Group(ZeroOrMore(p4header) & ZeroOrMore(p4action) & ZeroOrMore(p4parser) & Optional(p4starter))
    parsed = p4.parseString(spec)[0]
    grouped = {'headers':[], 'parsers':[], 'actions':[]}
    for group in parsed:
        if 'header' in group:
            grouped['headers'].append(group)
        elif 'parser' in group.asList():
            grouped['parsers'].append(group[1:])
        elif 'action' in group.asList():
            grouped['actions'].append(group[1:])
        else:
            raise Exception("Part of P4 description not categoriased!")
    return grouped


def parse_headers(headers):
    header =  p4_header()
    all_headers = ZeroOrMore(header)
    return all_headers.parseString(headers)
  
        
def parse_parsers(parsers):
    parser, starter = p4_parser()
    all_parsers = Group(starter & OneOrMore(parser))
    return all_parsers.parseString(parsers)[0]
   
          
def parse_actions(actions):
    action = p4_action()
    all_actions = ZeroOrMore(action)
    return all_actions.parseString(actions)
    
 
# ------------- TESTING  -------------------------------------------------------------------------------------        

class TestParseHeaders(unittest.TestCase):
    def setUp(self):
        self.text = """
            header ethernet {
                fields {
                    dst_addr : 48;
                    src_addr : 48;
                    ethertype : 16;
                }
            }
             header ictp {   
                fields {
                  nid : 32; 
                  csn : 32;   
                }
              }
        """
        self.result =str([{'header': 'ethernet', 
                                'fields': [{'field': 'dst_addr', 'length': '48'}, 
                                                {'field': 'src_addr', 'length': '48'},
                                                {'field': 'ethertype', 'length': '16'}]
                              }, 
                              {'header': 'ictp', 
                                'fields':  [{'field': 'nid', 'length': '32'},
                                                 {'field': 'csn', 'length': '32'}]
                              }
                            ])

    def test(self):
        parsed = parse_headers(self.text)
        self.assertEqual(str(parsed), self.result)

class TestParseParsers(unittest.TestCase):
    def setUp(self):
        self.text = """
              parser start {
                ethernet;
              }
              parser ethernet {
                switch(ethertype) { 
                  case 0x9100: ictp;
                  case 0x800: ipv4;
                }
              }
        """
        self.result =str([['parser', 'start', 'ethernet'],
                              ['parser', 'ethernet', 'ethertype', {'ictp': '0x9100', 'ipv4': '0x800'}]
                            ])

    def test(self):
        parsed = parse_parsers(self.text)
        self.assertEqual(str(parsed), self.result)
        
class TestParseActions(unittest.TestCase):
    def setUp(self):
        self.text = """
            action push_ictp {
                add_header(ictp, sizeof(ethernet));
            }
            action pop_ictp {
                remove_header(ictp, sizeof(ethernet));
            }
            action nothing_ictp {
                add_header(ictp, sizeof(ethernet));
                remove_header(ictp, sizeof(ethernet));
            }
        """
        self.result =str([['action', 'push_ictp', {'function': 'add_header', 
                                                                    'header': 'ictp', 
                                                                    'offset': {'sizeof': 'ethernet'}}
                               ],
                               ['action', 'pop_ictp', {'function': 'remove_header', 
                                                                    'header': 'ictp', 
                                                                    'offset': {'sizeof': 'ethernet'}}
                                ],
                                ['action', 'nothing_ictp', {'function': 'add_header', 
                                                                           'header': 'ictp', 
                                                                           'offset': {'sizeof': 'ethernet'}
                                                                          }, 
                                                                          {'function': 'remove_header', 
                                                                            'header': 'ictp', 
                                                                            'offset': {'sizeof': 'ethernet'}
                                                                          }
                                ]
                            ])
    def test(self):
        parsed = parse_actions(self.text)
        self.assertEqual(str(parsed), self.result)

if __name__ == "__main__":
    unittest.main()