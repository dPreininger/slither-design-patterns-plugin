from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from plugin.detectors.utils import is_deployable, is_overriden

class ContractInfo(AbstractDetector):
    '''
    Documentation
    '''

    ARGUMENT = 'contract-info'
    HELP = 'Help printed by slither'
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'Wiki'

    WIKI_TITLE = 'wiki title'
    WIKI_DESCRIPTION = 'wiki desc'
    WIKI_EXPLOIT_SCENARIO = 'wiki scenario'
    WIKI_RECOMMENDATION = 'wiki rec'

    def _detect(self):
        info = []
        
        for contract in filter(lambda c: is_deployable(c), self.slither.contracts):
            funcs = list(filter(lambda func: not func.is_constructor and not is_overriden(func), contract.functions))
            public_funcs = list(filter(lambda func: func.visibility in ('public', 'external'), funcs))

            info.append(f'DETECTOR INFO: Contract {contract.name} has {len(funcs)} functions. {len(public_funcs)} of them are public.\n\n')

        res = self.generate_result(info)

        if info:
            return [res]
        
        return []
    