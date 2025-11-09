import wikipedia # type: ignore
from typing import Any, List, Dict

# Utils
from . import variables

__version__ = "0.0.1"

class archiveSearch:

    """
    *-- Archive.org Searching --*

    """

    def __init__(self,
                 logger:Any=None):
        self.logger = logger
        self.variable = variables.variables(logger=self.logger)
        self.history = {}

    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

class wikiSearch:

    """
    *-- Wikipedia Searching --*
    """

    def __init__(self,
                 logger:Any=None,
                 confHandle:Any=None):
        self.logger = logger
        self.confHandle = confHandle
        self.config = {
            'resultCount':5,
            'summaryCharacterMax':200,
            'linksMax':5,
            'appendHistory':1
        }
        self.history = {}

        # Configuration
        if self.confHandle:
            if self.confHandle.dataRead:
                newConf = self.confHandle.index("utils:search")[1]
                newConf = self.confHandle.relateData(newConf,self.config)
                self.logPipe("__init__",f"Configured from confHandle.",e={'data':str(newConf)})
                self.config = newConf
    ## history
    # append
    def _historyAppend(self,searchResults:list[str],pageData:Dict[str,Any]):
        """
        Appends Page Data To `self.history`.

        Methodology:
            
            - Using len(self.history) we can create keys that incriment on appending data.
            - The key is '<len(self.history)>:(<searchResultItem>,...)'

        Args:
            searchResults (list[str]): searchResults from `self.getResults`
            pageData (dict): pageData from `self.buildPageData`.
                             This is called at the end of the process.

        Returns: None
        """
        historyID = str(len(self.history))
        searchResultString = str(f"{str(historyID)}:({str(', ').join(searchResults)})")
        self.logPipe("_historyAppend",f"Appending page data to history with key: '{str(searchResultString)}'")
        self.history[str(searchResultString)]=pageData

    ## Main
    # Get search results
    def getResults(self,searchString:str|List[str],resultCount:int=None)->List[str]:
        """
        Returns Wikipedia Page Results From A Search.

        Args:
            searchString (str,list[str]): Search querie(s).
            resultCount (int, optional): Amount of results to resolve.

        Returns: list[str]
        """
        resultCount = resultCount if resultCount else self.config.get('resultCount')
        uniqueResults = set()
        if not isinstance(searchString,(str,list)):
            eM = f"Argument `searchString` was not (str|list) type(s), got: {str(self.variable.getType(searchString))}"
            self.logPipe("getResults",eM,l=2)
            raise TypeError(str(eM))
        if isinstance(searchString,str): searchString = [str(searchString)]
        # Log
        self.logPipe("getResults",f"Preparing wikipedia query on {str(len(searchString))} items.")
        # Search
        for searchResult in searchString:
            if not isinstance(searchResult,str) or not searchResult.strip(): continue
            try:
                wikiReturn = wikipedia.search(str(searchResult),results=resultCount)
                if wikiReturn:
                    for item in wikiReturn:
                        self.logPipe("getResults",f"Appending '{str(item)}' to the set from search result: '{str(searchResult)}'.")
                        uniqueResults.add(item)
            except Exception as E:
                self.logPipe("getResults",f"Caught exception when attempting search on '{str(searchResult)}': {str(E)}",l=2)
                continue
        # Return
        return list(uniqueResults)

    # Build page data
    def buildPageData(self,searchResults:List[str])->Dict:
        """
        Builds A Dictionary Of Data Based Off Search Results From `self.getResults`.

        Page Data:
            {
                '{title}(pageID)':{
                    'pageQuery':str(page),
                    'ID':str(pageID),
                    'title':wikiPageData.title,
                    'url':wikiPageData.url,
                    'content':wikiPageData.content,
                    'images':wikiPageData.images,
                    'references':wikiPageData.references,
                    'summary':str(wikiPageData.summary[:int(maxSum)]) if maxSum != 0 else wikiPageData.summary,
                    'links':wikiPageData.links[:int(maxLinks)]
                }
            }

        Args:
            searchResults (str|list[str]): Result from `self.getResults`

        Returns: dict
        """
        # Validate
        if not isinstance(searchResults,list):
            raise TypeError(f"")
        if len(searchResults) == 0:
            raise ValueError(f"")
        # Prepare
        wikiPages = {}
        maxSum = self.config.get('summaryCharacterMax')
        maxLinks = self.config.get('linksMax')
        # Log
        self.logPipe("buildPageData",f"Preparing to retrieve page data on {str(len(searchResults))} pages.",e={
            'searchResults':str(searchResults),
            'summary character max':str(maxSum),
            'maximum links':str(maxLinks)
        })
        # Process
        pageCount = 0
        for page in searchResults:
            pageCount += 1
            try:
                # Get the data and compile
                wikiPageData = wikipedia.page(str(page),auto_suggest=False)
                pageID = wikiPageData.pageid
                pageCompiled = {
                    'pageQuery':str(page),
                    'ID':str(pageID),
                    'title':wikiPageData.title,
                    'url':wikiPageData.url,
                    'content':wikiPageData.content,
                    'images':wikiPageData.images,
                    'references':wikiPageData.references,
                    'summary':str(wikiPageData.summary[:int(maxSum)]) if maxSum != 0 else wikiPageData.summary,
                    'links':wikiPageData.links[:int(maxLinks)]
                }
                # Append and log
                wikiPages[f"{pageCompiled['title']}({str(pageID)})"]=pageCompiled
                self.logPipe("buildPageData",f"Compiled page({str(pageCount)}) '{str(page)}'.",e={'compiled':str(pageCompiled)})
            except wikipedia.exceptions.PageError as E:
                self.logPipe("buildPageData",f"Page({str(pageCount)}):'{str(page)}' was not found, exception: {str(E)}",l=2)
            except wikipedia.exceptions.DisambiguationError as E:
                self.logPipe("buildPageData",f"Page({str(pageCount)}):'{str(page)}' was skipped due to disambiguation, exception: {str(E)}",l=2)
            except Exception as E:
                self.logPipe("buildPageData",f"Page({str(pageCount)}):'{str(page)}' trigger an unexpected exception: {str(E)}",l=2)
        # Append and return
        self._historyAppend(searchResults,wikiPages)
        return wikiPages

    # Build and search
    def search(self,searchQueries:str|List[str],resultCount:int=None):
        """"""
        if isinstance(searchQueries,str): searchQueries=[str(searchQueries)]
        if not isinstance(searchQueries,list):
            
            raise TypeError(f"")
        self.logPipe("search",f"Getting searchResults for {str(len(searchQueries))} queries.")
        searchResults = self.getResults(searchQueries,resultCount=resultCount)
        self.logPipe("search",f"Found {str(len(searchResults))} search results, build page data.")
        pageData = self.buildPageData(searchResults)
        self.logPipe("search",f"Finish search on {str(len(searchQueries))} queries.",e=pageData)
        return pageData

    ## Main
    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)