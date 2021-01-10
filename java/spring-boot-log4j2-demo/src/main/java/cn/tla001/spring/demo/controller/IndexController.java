package cn.tla001.spring.demo.controller;

import cn.tla001.spring.demo.plugin.LogAlarmFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
    private static final Logger logger = LoggerFactory.getLogger(IndexController.class);

    @RequestMapping("/addItem")
    public Boolean addFilterItem(@RequestParam(name = "item") String item){

        return LogAlarmFilter.addFilterItem(item);
    }

    @RequestMapping("/delItem")
    public Boolean delFilterItem(@RequestParam(name = "item") String item){

        return LogAlarmFilter.delFilterItem(item);
    }

    @RequestMapping("/doTest")
    public void doTest(@RequestParam(name = "item") String item){
        logger.error("DoTest {}", item);
    }
}
