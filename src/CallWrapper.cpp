#include "CallWrapper.hh"

using namespace llvm;

void pdg::CallWrapper::buildActualTreeForArgs(FunctionWrapper &callee_fw)
{
  Function* called_func = callee_fw.getFunc();
  // we don't handle varidic function at the moment
  if (called_func->isVarArg())
    return;
  // construct actual tree based on the type signature of callee
  auto formal_arg_list = callee_fw.getArgList();
  assert(_arg_list.size() == formal_arg_list.size() && "actual/formal arg size don't match!");
  // iterate through actual param list and construct actual tree by copying formal tree
  auto actual_arg_iter = _arg_list.begin();
  auto formal_arg_iter = formal_arg_list.begin();
  while (actual_arg_iter != _arg_list.end())
  {
    Tree* arg_formal_in_tree = callee_fw.getArgFormalInTree(**formal_arg_iter);
    // build actual in tree
    Tree* arg_actual_in_tree = new Tree(*arg_formal_in_tree);
    arg_actual_in_tree->setTreeNodeType(GraphNodeType::ACTUAL_IN);
    arg_actual_in_tree->build();
    _arg_actual_in_tree_map.insert(std::make_pair(*actual_arg_iter, arg_actual_in_tree));
    // build actual out tree
    Tree* arg_actual_out_tree = new Tree(*arg_formal_in_tree);
    arg_actual_out_tree->setTreeNodeType(GraphNodeType::ACTUAL_OUT);
    arg_actual_out_tree->build();
    _arg_actual_out_tree_map.insert(std::make_pair(*actual_arg_iter, arg_actual_out_tree));

    actual_arg_iter++;
    formal_arg_iter++;
  }
}

pdg::Tree *pdg::CallWrapper::getArgActualInTree(Value &actual_arg)
{
  auto iter = _arg_actual_in_tree_map.find(&actual_arg);
  if (iter == _arg_actual_in_tree_map.end())
    return nullptr;
  return _arg_actual_in_tree_map[&actual_arg];
}

pdg::Tree *pdg::CallWrapper::getArgActualOutTree(Value &actual_arg)
{
  auto iter = _arg_actual_out_tree_map.find(&actual_arg);
  if (iter == _arg_actual_out_tree_map.end())
    return nullptr;
  return _arg_actual_out_tree_map[&actual_arg];
}