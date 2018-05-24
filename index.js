'use strict';

const processUtils = require('./build/Release/processUtils.node');

console.log(`native addon getProcessId->calc.exe: ${processUtils.getProcessId('Calculator.exe')}`);

console.log(processUtils);