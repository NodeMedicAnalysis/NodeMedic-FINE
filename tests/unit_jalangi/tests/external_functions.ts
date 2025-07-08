import { __jalangi_assert_taint_true__, __jalangi_assert_taint_false__, 
    __jalangi_set_taint__, __jalangi_set_prop_taint__, __jalangi_assert_prop_taint_false__,
    __jalangi_assert_prop_taint_true__} from "../../taint_header";
import { test_suite, test_one } from "../../test_header";
import { basename } from 'path';

test_suite("---------- External function --------", function() {
    var a = '/a/b/c.d';

    test_one("Setting taint on a", function() {
        __jalangi_set_taint__(a);
    });

    let b = basename(a);

    test_one("path.basename(a) should be tainted", function () {
        __jalangi_assert_taint_true__(b);
    });
});
