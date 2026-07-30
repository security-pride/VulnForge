import io.shiftleft.codepropertygraph.generated.nodes._
import scala.collection.mutable
import java.io.PrintWriter
import spray.json._
import DefaultJsonProtocol._
import ScalaReplPP.JsonProtocol.resultFormat
import scala.jdk.CollectionConverters._


case class Result(
  calleeMethods: List[(String, String, String, Int)],
  callerMethods: List[(String, String, String, Int)],
  typeDefs: List[(String, String)],
  globalVars: List[String],
  importContext: List[String],
  vulnerableMethods: List[(String, String, String, Int)], 
  visitedLines: List[(Int, String, String)],
  visitedParams: List[(String, String, String)]
)

object JsonProtocol extends DefaultJsonProtocol {
  implicit val resultFormat: RootJsonFormat[Result] = jsonFormat8(Result)
}

@main def exec(cpgFile: String, outFile: String, methodnameList: String, filename: String, lineNumbers: String) = {
  
  importCpg(cpgFile)

  def resolveTypedef(typeDecl: TypeDecl): TypeDecl = {
    val visited = mutable.Set[String]()
    var current = typeDecl
    while (current.aliasTypeFullName.isDefined && !visited.contains(current.fullName)) {
        visited.add(current.fullName)
        val nextFullName = current.aliasTypeFullName.get
        cpg.typeDecl.fullName(nextFullName).headOption match {
            case Some(nextTypeDecl) => current = nextTypeDecl
            case None => return current
        }
    }
    current
  }

  
  val lines = lineNumbers.split(",").map(_.toInt)
  val methodnames = methodnameList.split(",")
  val allImports = cpg.file.filter(_.name.matches(s".*${filename}"))._namespaceBlockViaAstOut._astOut.filter(_.isInstanceOf[Import]).cast[Import].code.dedup.toList

  
  val allVisitedLines = mutable.Set.empty[(Int, String, String)]
  val allCalleeMethods = mutable.Set.empty[(String, String, String, Int)]
  val allCallerMethods = mutable.Set.empty[(String, String, String, Int)]
  val allTypesDefs = mutable.Set.empty[(String, String)]
  val allGlobalVars = mutable.Set.empty[String]
  val allVisitedParams = mutable.Set.empty[(String, String, String)]


  val vulnerableMethod = cpg.method.filter(m => methodnames.contains(m.name)).filter(_.filename.matches(s".*${filename}")).toList
  val vulnerableMethodInfo = vulnerableMethod.map(m => (m.filename, m.name, m.toList.dumpRaw.head, m.lineNumber.getOrElse(0)))

  vulnerableMethod.caller.filterNot(m => m.filename.contains("<")).map(m => (m.filename, m.name, m.toList.dumpRaw.head, 1)).dedup.foreach(allCallerMethods.add)

  lines.foreach { lineNumber =>
    val startNodes = cpg.method.filter(m => methodnames.contains(m.name)).filter(_.filename.matches(s".*${filename}")).ast.lineNumber(lineNumber).toList
    if (startNodes.nonEmpty) {
      val visited = mutable.Set.empty[StoredNode]
      val callee = mutable.Set.empty[Method]
      val types = mutable.Set.empty[TypeDecl]
      val globals = mutable.Set.empty[Local]
      val queue = mutable.Queue.empty[StoredNode]
      queue.enqueueAll(startNodes)
      while (queue.nonEmpty) {
        val currentNode = queue.dequeue()
        if (!visited.contains(currentNode) && methodnames.contains(currentNode.location.methodShortName)) {
          visited.add(currentNode)
          if (currentNode.isInstanceOf[MethodParameterIn]) {
            allVisitedParams.add((currentNode.asInstanceOf[MethodParameterIn].code, currentNode.location.methodShortName, currentNode.location.filename))
          }
          allVisitedLines.add((currentNode.propertiesMap.asScala.getOrElse("LINE_NUMBER", Integer.valueOf(0)).asInstanceOf[Integer].intValue(), currentNode.location.methodShortName, currentNode.location.filename))
          callee.addAll(currentNode._callOut.cast[Method].toList)
          val tmp_types = currentNode._evalTypeOut._refOut.cast[TypeDecl].map(t => t.name).toList
          tmp_types.foreach(t => {
            val base_t = t.replaceAll("\\*", "")
            val typeDecls = cpg.typeDecl(base_t).filter(t => t.lineNumber.isDefined).toList
            if (typeDecls.nonEmpty) {
                val preferredDecls = typeDecls.filter { d =>
                    val code = d.code.trim
                    (((code.startsWith("struct") || code.startsWith("union") || code.startsWith("enum")) && code.contains("{"))) || code.startsWith("typedef")
                }

                if (preferredDecls.nonEmpty) {
                    val declToUse = preferredDecls.sortBy(t => -t.code.length).head
                    types.add(resolveTypedef(declToUse))
                }
            }
          })
          globals.addAll(currentNode._refOut.filter(m => m.location.methodShortName.equals("<global>")).cast[Local].toList)
          queue.enqueueAll(currentNode._reachingDefIn.toList)
          queue.enqueueAll(currentNode._cdgIn.toList)
          queue.enqueueAll(currentNode._argumentOut.toList)
        }
      }
      visited.clear() 
      queue.clear()   
      queue.enqueueAll(startNodes)
      while (queue.nonEmpty) {
        val currentNode = queue.dequeue()
        if (!visited.contains(currentNode) && methodnames.contains(currentNode.location.methodShortName)) {
          visited.add(currentNode)
          allVisitedLines.add((currentNode.propertiesMap.asScala.getOrElse("LINE_NUMBER", Integer.valueOf(0)).asInstanceOf[Integer].intValue(), currentNode.location.methodShortName, currentNode.location.filename))
          callee.addAll(currentNode._callOut.cast[Method].toList)
          val tmp_types = currentNode._evalTypeOut._refOut.cast[TypeDecl].map(t => t.name).toList
          tmp_types.foreach(t => {
            val base_t = t.replaceAll("\\*", "")
            val typeDecls = cpg.typeDecl(base_t).filter(t => t.lineNumber.isDefined).toList
            if (typeDecls.nonEmpty) {
                val preferredDecls = typeDecls.filter { d =>
                    val code = d.code.trim
                    (((code.startsWith("struct") || code.startsWith("union") || code.startsWith("enum")) && code.contains("{"))) || code.startsWith("typedef")
                }

                if (preferredDecls.nonEmpty) {
                    val declToUse = preferredDecls.sortBy(t => -t.code.length).head
                    types.add(resolveTypedef(declToUse))
                }
            }
          })
          globals.addAll(currentNode._refOut.filter(m => m.location.methodShortName.equals("<global>")).cast[Local].toList)
          queue.enqueueAll(currentNode._reachingDefOut.toList)  
          queue.enqueueAll(currentNode._cdgOut.toList)          
          queue.enqueueAll(currentNode._argumentOut.toList)      
        }
      }
      allCalleeMethods ++= callee.map(t => (t.filename, t.name, t.toList.dumpRaw.head, 1)).dedup
      allTypesDefs ++= types.map(t => (t.code, t.name)).dedup
      allGlobalVars ++= globals.map(t => t.code).dedup
    }
  }
  val maxDepth = 3
  val methodsToProcess = mutable.Queue[(String, String, String, Int)]()
  methodsToProcess.enqueueAll(allCalleeMethods)
  val processedMethods = mutable.Set[(String, String)]()
  processedMethods ++= allCalleeMethods.map(m => (m._1, m._2))
  while (methodsToProcess.nonEmpty) {
    val (filename, methodName, raw, depth) = methodsToProcess.dequeue()
    if (depth < maxDepth) {
      val nextLevelCalls = cpg.method
        .name(methodName)
        .filter(_.filename == filename)
        .callee
        .filterNot(m => m.filename.contains("<"))
        .map(m => (m.filename, m.name, m.toList.dumpRaw.head, depth + 1))
        .dedup
        .toList
      for (call <- nextLevelCalls if !processedMethods.contains((call._1, call._2))) {
        allCalleeMethods.add(call)
        methodsToProcess.enqueue(call)
        processedMethods.add((call._1, call._2))
      }
    }
  }
  val allMethodsForGlobals = allCalleeMethods.map(m => (m._1, m._2)) ++ allCallerMethods.map(m => (m._1, m._2))
  allMethodsForGlobals.foreach { case (filename, methodName) =>
    cpg.method.name(methodName).filter(_.filename == filename)
      .flatMap(_.ast.isIdentifier.refsTo)
      .collect { case l: Local if l.method.fullName.l.contains("<global>") => l.code }
      .dedup
      .foreach(allGlobalVars.add)
  }
  val result = Result(
    calleeMethods = allCalleeMethods.toList,
    callerMethods = allCallerMethods.toList,
    typeDefs = allTypesDefs.toList,
    globalVars = allGlobalVars.toList,
    importContext = allImports,
    vulnerableMethods = vulnerableMethodInfo.toList,
    visitedLines = allVisitedLines.toList,
    visitedParams = allVisitedParams.toList
  )
  val json = result.toJson.prettyPrint
  new PrintWriter(outFile) {
    write(json)
    close()
  }
  println(s"${outFile} saved.")
}
