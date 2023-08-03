from slither.core.declarations.function import Function

def explore_functions(function: Function):
        values = function.expressions
        explored = [function]
        to_explore = [
            c for c in function.internal_calls if isinstance(c, Function) and c not in explored
        ]
        to_explore += [
            c for (_, c) in function.library_calls if isinstance(c, Function) and c not in explored
        ]
        to_explore += [m for m in function.modifiers if m not in explored]

        while to_explore:
            f = to_explore[0]
            to_explore = to_explore[1:]
            if f in explored:
                continue
            explored.append(f)

            values += f.expressions

            to_explore += [
                c
                for c in f.internal_calls
                if isinstance(c, Function) and c not in explored and c not in to_explore
            ]
            to_explore += [
                c
                for (_, c) in f.library_calls
                if isinstance(c, Function) and c not in explored and c not in to_explore
            ]
            to_explore += [m for m in f.modifiers if m not in explored and m not in to_explore]

        # Remove duplicates
        # Even though this method is fairly slow, it works on unhashable types
        res = []
        [res.append(x) for x in values if x not in res]
        return res