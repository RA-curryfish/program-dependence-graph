#ifndef CONTROLDEPENDENCYGRAPH_H_
#define CONTROLDEPENDENCYGRAPH_H_
#include "Graph.hh"
#include "PDGCallGraph.hh"
#include "ControlDepLib.hh"

namespace pdg
{
  class ControlDependencyGraph : public llvm::FunctionPass
  {
  public:
    static char ID;
    ControlDependencyGraph() : llvm::FunctionPass(ID){};
    void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
    llvm::StringRef getPassName() const override { return "Control Dependency Graph"; }
    bool runOnFunction(llvm::Function &F) override;
    void addControlDepFromNodeToBB(Node &n, llvm::BasicBlock &bb, EdgeType edge_type);
    void addControlDepFromEntryNodeToEntryBlock(llvm::Function &F);
    void addControlDepFromDominatedBlockToDominator(llvm::Function &F);
    std::unordered_set<llvm::BasicBlock *> findAllIntraprocSuccBB(llvm::BasicBlock &BB);
  private:
    llvm::ControlDependenceGraph *_CDG;
  };
} // namespace pdg

#endif