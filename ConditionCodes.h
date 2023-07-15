//
// The condition code in warbird.h always need to be in sync with the condition
// codes in runtime\ConditionCodes.h
//
enum ConditionCode
{
    ConditionCodeNone,
    ConditionCodeEq,
    ConditionCodeGe,
    ConditionCodeGt,
    ConditionCodeLbc,
    ConditionCodeLbs,
    ConditionCodeLe,
    ConditionCodeLt,
    ConditionCodeNe,
    ConditionCodeNo,
    ConditionCodeNp,
    ConditionCodeNs,
    ConditionCodeO,
    ConditionCodeP,
    ConditionCodeS,
    ConditionCodeUge,
    ConditionCodeUgt,
    ConditionCodeUle,
    ConditionCodeULt,
    ConditionCodeBt,             // Check if the specified bit is set
    ConditionCodeUnknown = 0xff, // special case for unexpected values
};
