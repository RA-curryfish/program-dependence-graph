#ifndef RISKY_FIELD_ANALYSIS_H_
#define RISKY_FIELD_ANALYSIS_H_
#include "SharedDataAnalysis.hh"
#include "json.hpp"

namespace pdg
{
    class RiskyFieldAnalysis : public llvm::ModulePass
    {
        public:
            static char ID;
            RiskyFieldAnalysis() : llvm::ModulePass(ID){};
            void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
            llvm::StringRef getPassName() const override { return "Risky Field Analysis"; }
            bool runOnModule(llvm::Module &M) override;
            bool isDriverControlledField(TreeNode &tn);
            llvm::Function *canReachSensitiveOperations(Node &srcFuncNode);
            void classifyRiskyFieldDirectUse(TreeNode &tn);
            void classifyRiskyFieldTaint(TreeNode &tn);
            // pointer field checks
            bool checkPtrValUsedInPtrArithOp(Node &n);
            // scalar field checks
            bool checkValUsedAsArrayIndex(Node &n);
            bool checkIsArrayAccess(llvm::Instruction &inst);
            // generic field checks
            static bool checkValUsedInPtrArithOp(Node &n);
            bool checkValUsedInSenBranchCond(Node &n, llvm::raw_fd_ostream &OS, std::string &senTypeStr);
            bool checkValInSecurityChecks(Node &n);
            static bool checkValUsedInSensitiveOperations(Node &n, std::string &senOpName);
            bool checkValUsedInInlineAsm(Node &n);
            bool isSensitiveOperation(llvm::Function &F);
            bool hasUpdateInDrv(TreeNode &n);
            // print helpers
            void printRiskyFieldInfo(llvm::raw_ostream &os, const std::string &category, TreeNode &treeNode, llvm::Function &func, llvm::Instruction &inst);
            void printTaintTrace(llvm::Instruction &source, llvm::Instruction &sink, std::string fieldHierarchyName, std::string flowType, llvm::raw_fd_ostream &OS);
            void getTraceStr(llvm::Instruction &source, llvm::Instruction &sink, std::string fieldHierarchyName, std::string flowType, llvm::raw_string_ostream &OS);
            void printFieldDirectUseClassification(llvm::raw_fd_ostream &OS);
            void printFieldClassificationTaint(llvm::raw_fd_ostream &OS);
            void printTaintFieldInfo();
            void printTaintTraceAndConditions(Node &srcNode, Node &dstNode, std::string accessPathStr, std::string taintType, unsigned caseId);

        private:
            llvm::Module *_module;
            ProgramGraph *_PDG;
            SharedDataAnalysis *_SDA;
            PDGCallGraph *_callGraph;
            // store taint source/sink pair
            std::set<std::tuple<Node *, Node *, std::string, std::string>> _taintTuples;
            // stats counting
            unsigned numKernelReadDriverUpdatedFields = 0;
            unsigned numPtrField = 0;
            unsigned numFuncPtrField = 0;
            unsigned numDataPtrField = 0;
            // counting based on direct uses
            unsigned numPtrArithPtrField = 0;
            unsigned numDereferencePtrField = 0;
            unsigned numSensitiveOpPtrField = 0;
            unsigned numBranchPtrField = 0;
            // scalar field direct use
            unsigned numArrayIdxField = 0;
            unsigned numArithField = 0;
            unsigned numSensitiveBranchField = 0;
            unsigned numSensitiveOpsField = 0;
            // unclassified field direct use
            unsigned numUnclassifiedField = 0;
            unsigned numUnclassifiedFuncPtrField = 0;
            // taint ptr field classification
            unsigned numPtrArithPtrFieldTaint = 0;
            unsigned numDereferencePtrFieldTaint = 0;
            // unsigned numDereferencePtrFieldTaint = 0;
            unsigned numSensitiveOpPtrFieldTaint = 0;
            unsigned numBranchPtrFieldTaint = 0;
            // taint scalar field classification
            unsigned numArrayIdxFieldTaint = 0;
            unsigned numArithFieldTaint = 0;
            unsigned numSensitiveBranchFieldTaint = 0;
            unsigned numSensitiveOpsFieldTaint = 0;
            // unclassified field taint
            unsigned numUnclassifiedFieldTaint = 0;
            unsigned numUnclassifiedFuncPtrFieldTaint = 0;
            unsigned numKernelAPIParam = 0;
            unsigned numControlTaintTrace = 0;
            // output file
            llvm::raw_fd_ostream *riskyFieldOS;
            llvm::raw_fd_ostream *riskyFieldTaintOS;
            nlohmann::ordered_json taintTracesJson = nlohmann::ordered_json::array();
            nlohmann::ordered_json taintTracesJsonNoConds = nlohmann::ordered_json::array();
            nlohmann::ordered_json unclassifiedFieldsJson = nlohmann::ordered_json::array();
            unsigned unclassifiedFieldCount = 0;
    };
}

#endif