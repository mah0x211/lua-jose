--[[

  Copyright (C) 2014 Masatoshi Teruya
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
 
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
 
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

  none.lua
  lua-jose
  
  Created by Masatoshi Teruya on 14/11/04.
  
--]]

-- module
local util = require('jose.util');
-- class
local None = require('halo').class.None;


function None:init( jwk )
    self.jwk = jwk;
    return self;
end


function None:sign()
    return nil;
end


function None:verify()
    return true;
end


function None:createToken( claims )
    local own = protected(self);
    local token = {};
    local sig, err;
    
    token[1], err = util.encodeToken({
        alg = 'none',
        kid = self.jwk.kid
    });
    if err then
        return nil, err;
    end
    
    token[2], err = util.encodeToken( claims );
    if err then
        return nil, err;
    end
    
    return table.concat( token, '.' );
end


return None.exports;
